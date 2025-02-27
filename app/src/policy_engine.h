// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "cose.h"
#include "http_error.h"
#include "profiles.h"
#include "tracing.h"

#include <ccf/js/common_context.h>
#include <chrono>
#include <rego/rego.hh>
#include <string>

namespace scitt
{
  using PolicyScript = std::string;

  namespace js
  {
    static inline ccf::js::core::JSWrappedValue claim_profile_to_js_val(
      ccf::js::core::Context& ctx, SignedStatementProfile claim_profile)
    {
      switch (claim_profile)
      {
        case SignedStatementProfile::IETF:
        {
          return ctx.new_string("IETF");
        }
        case SignedStatementProfile::X509:
        {
          return ctx.new_string("X509");
        }
        default:
        {
          throw std::logic_error("Unhandled SignedStatementProfile value");
        }
      }
    }

    static inline ccf::js::core::JSWrappedValue protected_header_to_js_val(
      ccf::js::core::Context& ctx, const scitt::cose::ProtectedHeader& phdr)
    {
      auto obj = ctx.new_obj();

      // Vanilla SCITT protected header parameters
      {
        if (phdr.alg.has_value())
        {
          obj.set_int64("alg", phdr.alg.value());
        }

        if (phdr.crit.has_value())
        {
          auto crit_array = ctx.new_array();
          size_t i = 0;

          for (const auto& e : phdr.crit.value())
          {
            if (std::holds_alternative<int64_t>(e))
            {
              crit_array.set_at_index(
                i++,
                ccf::js::core::JSWrappedValue(
                  ctx, JS_NewInt64(ctx, std::get<int64_t>(e))));
            }
            else if (std::holds_alternative<std::string>(e))
            {
              crit_array.set_at_index(
                i++, ctx.new_string(std::get<std::string>(e)));
            }
          }

          obj.set("crit", std::move(crit_array));
        }

        if (phdr.kid.has_value())
        {
          obj.set("kid", ctx.new_string(phdr.kid.value()));
        }

        if (phdr.issuer.has_value())
        {
          obj.set("issuer", ctx.new_string(phdr.issuer.value()));
        }

        if (phdr.feed.has_value())
        {
          obj.set("feed", ctx.new_string(phdr.feed.value()));
        }

        if (phdr.iat.has_value())
        {
          obj.set_int64("iat", phdr.iat.value());
        }

        if (phdr.svn.has_value())
        {
          obj.set_int64("svn", phdr.svn.value());
        }

        if (phdr.cty.has_value())
        {
          if (std::holds_alternative<int64_t>(phdr.cty.value()))
          {
            obj.set_int64("cty", std::get<int64_t>(phdr.cty.value()));
          }
          else if (std::holds_alternative<std::string>(phdr.cty.value()))
          {
            obj.set(
              "cty", ctx.new_string(std::get<std::string>(phdr.cty.value())));
          }
        }

        if (phdr.x5chain.has_value())
        {
          auto x5_array = ctx.new_array();
          size_t i = 0;

          for (const auto& der_cert : phdr.x5chain.value())
          {
            auto pem = ccf::crypto::cert_der_to_pem(der_cert);
            x5_array.set_at_index(i++, ctx.new_string(pem.str()));
          }

          obj.set("x5chain", std::move(x5_array));
        }

        auto cwt = ctx.new_obj();
        if (phdr.cwt_claims.iss.has_value())
        {
          cwt.set("iss", ctx.new_string(phdr.cwt_claims.iss.value()));
        }
        if (phdr.cwt_claims.sub.has_value())
        {
          cwt.set("sub", ctx.new_string(phdr.cwt_claims.sub.value()));
        }
        if (phdr.cwt_claims.iat.has_value())
        {
          cwt.set_int64("iat", phdr.cwt_claims.iat.value());
        }
        if (phdr.cwt_claims.svn.has_value())
        {
          cwt.set_int64("svn", phdr.cwt_claims.svn.value());
        }
        obj.set("cwt", std::move(cwt));
      }

      return obj;
    }

    static inline std::optional<std::string> apply_js_policy(
      const PolicyScript& script,
      const std::string& policy_name,
      SignedStatementProfile claim_profile,
      const scitt::cose::ProtectedHeader& phdr)
    {
      auto start = std::chrono::system_clock::now();

      // Allow the policy to access common globals (including shims for
      // builtins) like "console", "ccf.crypto"
      ccf::js::CommonContext interpreter(ccf::js::TxAccess::APP_RO);

      ccf::js::core::JSWrappedValue apply_func;
      try
      {
        apply_func =
          interpreter.get_exported_function(script, "apply", policy_name);
      }
      catch (const std::exception& e)
      {
        throw BadRequestError(
          scitt::errors::PolicyError,
          fmt::format("Invalid policy module: {}", e.what()));
      }

      auto end = std::chrono::system_clock::now();
      auto elapsed =
        std::chrono::duration_cast<std::chrono::microseconds>(end - start);
      CCF_APP_INFO("JS policy compilation took {}us", elapsed.count());
      start = std::chrono::system_clock::now();

      auto profile_val = claim_profile_to_js_val(interpreter, claim_profile);
      auto phdr_val = protected_header_to_js_val(interpreter, phdr);

      const auto result = interpreter.call_with_rt_options(
        apply_func,
        {profile_val, phdr_val},
        ccf::JSRuntimeOptions{
          10 * 1024 * 1024, // max_heap_bytes (10MB)
          1024 * 1024, // max_stack_bytes (1MB)
          1000, // max_execution_time_ms (1s)
          true, // log_exception_details
          false, // return_exception_details
          0, // max_cached_interpreters
        },
        // Limits defined explicitly above
        ccf::js::core::RuntimeLimitsPolicy::NONE);

      if (result.is_exception())
      {
        auto [reason, trace] = interpreter.error_message();

        throw BadRequestError(
          scitt::errors::PolicyError,
          fmt::format(
            "Error while applying policy: {}\n{}",
            reason,
            trace.value_or("<no trace>")));
      }

      end = std::chrono::system_clock::now();
      elapsed =
        std::chrono::duration_cast<std::chrono::microseconds>(end - start);
      CCF_APP_INFO("JS policy execution took {}us", elapsed.count());

      if (result.is_str())
      {
        return interpreter.to_str(result);
      }

      // Note this does JS-style truthy conversion, so lots of truthy values may
      // become true here
      if (result.is_true())
      {
        return std::nullopt;
      }

      throw BadRequestError(
        scitt::errors::PolicyError,
        fmt::format(
          "Unexpected return value from policy: {}",
          interpreter.to_str(result)));
    }
  }

  // Returns nullopt for success, else a string describing why the policy was
  // refused. May also throw if given invalid policies, or policy execution
  // throws.
  static inline std::optional<std::string> check_for_policy_violations_js(
    const PolicyScript& script,
    const std::string& policy_name,
    SignedStatementProfile claim_profile,
    const cose::ProtectedHeader& phdr)
  {
    return js::apply_js_policy(script, policy_name, claim_profile, phdr);
  }

  using PolicyRego = std::string;

  static inline nlohmann::json rego_input_from_profile_and_protected_header(
    SignedStatementProfile claim_profile, const cose::ProtectedHeader& phdr)
  {
    nlohmann::json rego_input;
    rego_input["profile"] = claim_profile;
    nlohmann::json cwt;
    cwt["iss"] = phdr.cwt_claims.iss;
    cwt["sub"] = phdr.cwt_claims.sub;
    cwt["iat"] = phdr.cwt_claims.iat;
    cwt["svn"] = phdr.cwt_claims.svn;
    nlohmann::json protected_header;
    protected_header["cwt"] = cwt;
    protected_header["alg"] = phdr.alg;
    if (phdr.cty.has_value())
    {
      if (std::holds_alternative<int64_t>(phdr.cty.value()))
      {
        protected_header["cty"] = std::get<int64_t>(phdr.cty.value());
      }
      else if (std::holds_alternative<std::string>(phdr.cty.value()))
      {
        protected_header["cty"] = std::get<std::string>(phdr.cty.value());
      }
    }
    rego_input["phdr"] = protected_header;
    return rego_input;
  }

  static inline std::optional<std::string> check_for_policy_violations_rego(
    const PolicyScript& script,
    SignedStatementProfile claim_profile,
    const cose::ProtectedHeader& phdr)
  {
    auto start = std::chrono::system_clock::now();

    auto rego_input =
      rego_input_from_profile_and_protected_header(claim_profile, phdr);

    rego::Interpreter interpreter(true /* v1 compatible */);
    auto rv = interpreter.add_module("policy", script);
    if (rv != nullptr)
    {
      throw BadRequestError(
        scitt::errors::PolicyError, "Invalid policy module");
    }

    auto qv = interpreter.set_query("data.policy.allow");
    if (qv != nullptr)
    {
      throw BadRequestError(scitt::errors::PolicyError, "Invalid policy query");
    }

    auto end = std::chrono::system_clock::now();
    auto elapsed =
      std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    CCF_APP_INFO("Rego policy compilation and query setting took {}us", elapsed.count());
    start = std::chrono::system_clock::now();

    auto tv = interpreter.set_input_term(rego_input.dump());
    if (tv != nullptr)
    {
      throw BadRequestError(scitt::errors::PolicyError, "Invalid policy input");
    }

    auto sv = interpreter.output_to_string(interpreter.fast_query());
    end = std::chrono::system_clock::now();
    elapsed =
      std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    CCF_APP_INFO("Rego policy evaluation took {}us", elapsed.count());

    if (sv == "{\"expressions\":[true]}")
    {
      return std::nullopt;
    }
    else if (sv == "{\"expressions\":[false]}")
    {
      return "Input statement rejected";
    }
    else
    {
      throw BadRequestError(
        scitt::errors::PolicyError,
        fmt::format("Error while applying policy: {}", sv));
    }
  }
}