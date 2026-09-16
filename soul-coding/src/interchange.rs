//! Versioned JSON task interchange for external coding-harness adapters.
//!
//! This module provides a small, provider-neutral ingress format for wrappers
//! around the canonical SoulSystem coding runtime. It deliberately does not
//! claim protocol compatibility with any third-party coding agent: adapters
//! must translate their native task format into this explicit contract.

use crate::contract::ContractError;
use crate::{CheckSpec, CommandSpec, CommandSpecError, TaskSpec};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;

/// Stable schema identifier for the first coding-task interchange envelope.
pub const CODING_TASK_INTERCHANGE_SCHEMA_V1: &str = "soulsystem.coding-task/v1";

/// Serializable acceptance-check contract used at the JSON boundary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InterchangeCheckV1 {
    pub name: String,
    pub command: String,
    pub required: bool,
    pub timeout_secs: u64,
}

/// Versioned provider-neutral task envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CodingTaskEnvelopeV1 {
    pub schema: String,
    pub prompt: String,
    pub acceptance: Vec<InterchangeCheckV1>,
}

impl CodingTaskEnvelopeV1 {
    /// Parse a canonical v1 task envelope and validate all task/check fields.
    ///
    /// Unknown JSON fields are rejected to prevent adapters from assuming that
    /// silently ignored metadata influences execution.
    ///
    /// # Errors
    ///
    /// Returns a typed error for malformed JSON, an unsupported schema,
    /// duplicate check names, or any invalid canonical task/check field.
    pub fn from_json(payload: &str) -> Result<Self, CodingTaskInterchangeError> {
        let envelope: Self = serde_json::from_str(payload)?;
        envelope.validate()?;
        Ok(envelope)
    }

    /// Validate the envelope without creating runtime identity or timestamps.
    ///
    /// # Errors
    ///
    /// Returns a typed error when schema or acceptance-check fields are invalid.
    pub fn validate(&self) -> Result<(), CodingTaskInterchangeError> {
        if self.schema != CODING_TASK_INTERCHANGE_SCHEMA_V1 {
            return Err(CodingTaskInterchangeError::UnsupportedSchema(
                self.schema.clone(),
            ));
        }

        if self.prompt.trim().is_empty() {
            return Err(CodingTaskInterchangeError::Contract(
                ContractError::EmptyPrompt,
            ));
        }
        if self.acceptance.is_empty() {
            return Err(CodingTaskInterchangeError::Contract(
                ContractError::NoAcceptanceChecks,
            ));
        }

        let mut names = HashSet::with_capacity(self.acceptance.len());
        for check in &self.acceptance {
            let validated = CheckSpec::new(
                check.name.clone(),
                check.command.clone(),
                check.required,
                check.timeout_secs,
            )?;
            CommandSpec::parse(&validated.command)?;
            if !names.insert(validated.name.clone()) {
                return Err(CodingTaskInterchangeError::DuplicateCheckName(
                    validated.name,
                ));
            }
        }
        Ok(())
    }

    /// Convert a validated interchange envelope into the canonical runtime task.
    ///
    /// Runtime task identity and creation time are intentionally minted by
    /// [`TaskSpec::new`] at ingestion rather than accepted from an external
    /// adapter.
    ///
    /// # Errors
    ///
    /// Returns the same validation failures as [`Self::validate`].
    pub fn into_task_spec(self) -> Result<TaskSpec, CodingTaskInterchangeError> {
        self.validate()?;
        let checks = self
            .acceptance
            .into_iter()
            .map(|check| {
                CheckSpec::new(
                    check.name,
                    check.command,
                    check.required,
                    check.timeout_secs,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(TaskSpec::new(self.prompt, checks)?)
    }
}

/// Fail-closed task-interchange validation errors.
#[derive(Debug, Error)]
pub enum CodingTaskInterchangeError {
    #[error("invalid coding-task JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported coding-task schema: {0}")]
    UnsupportedSchema(String),
    #[error("duplicate acceptance-check name: {0}")]
    DuplicateCheckName(String),
    #[error(transparent)]
    Contract(#[from] ContractError),
    #[error(transparent)]
    Command(#[from] CommandSpecError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> &'static str {
        r#"{
            "schema":"soulsystem.coding-task/v1",
            "prompt":"fix the parser",
            "acceptance":[
                {"name":"unit","command":"cargo test -p parser","required":true,"timeout_secs":120},
                {"name":"fmt","command":"cargo fmt --all -- --check","required":false,"timeout_secs":30}
            ]
        }"#
    }

    #[test]
    fn valid_envelope_mints_canonical_runtime_task() {
        let task = CodingTaskEnvelopeV1::from_json(payload())
            .unwrap()
            .into_task_spec()
            .unwrap();
        assert_eq!(task.prompt, "fix the parser");
        assert_eq!(task.acceptance.len(), 2);
        assert!(task.acceptance[0].required);
        assert!(!task.acceptance[1].required);
        assert!(!task.id.is_empty());
    }

    #[test]
    fn unknown_fields_fail_closed() {
        let changed = payload().replace(
            "\"prompt\":\"fix the parser\"",
            "\"prompt\":\"fix the parser\",\"provider\":\"external\"",
        );
        assert!(matches!(
            CodingTaskEnvelopeV1::from_json(&changed),
            Err(CodingTaskInterchangeError::Json(_))
        ));
    }

    #[test]
    fn unsupported_schema_fails_closed() {
        let changed = payload().replace("soulsystem.coding-task/v1", "soulsystem.coding-task/v2");
        assert!(matches!(
            CodingTaskEnvelopeV1::from_json(&changed),
            Err(CodingTaskInterchangeError::UnsupportedSchema(schema))
                if schema == "soulsystem.coding-task/v2"
        ));
    }

    #[test]
    fn duplicate_check_names_are_rejected() {
        let changed = payload().replace("\"name\":\"fmt\"", "\"name\":\"unit\"");
        assert!(matches!(
            CodingTaskEnvelopeV1::from_json(&changed),
            Err(CodingTaskInterchangeError::DuplicateCheckName(name)) if name == "unit"
        ));
    }

    #[test]
    fn invalid_check_fields_use_canonical_contract_validation() {
        let changed = payload().replace("\"timeout_secs\":30", "\"timeout_secs\":0");
        assert!(matches!(
            CodingTaskEnvelopeV1::from_json(&changed),
            Err(CodingTaskInterchangeError::Contract(
                ContractError::InvalidCheckTimeout
            ))
        ));
    }

    #[test]
    fn shell_syntax_is_rejected_before_runtime_task_creation() {
        let changed = payload().replace(
            "cargo test -p parser",
            "cargo test -p parser && echo unexpected",
        );
        assert!(matches!(
            CodingTaskEnvelopeV1::from_json(&changed),
            Err(CodingTaskInterchangeError::Command(
                CommandSpecError::ShellSyntax
            ))
        ));
    }
}
