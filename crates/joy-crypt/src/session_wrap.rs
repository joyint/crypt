//! Job-bound session wraps.
//!
//! When a status change creates a Job for an AI assignee on an
//! encrypted item, the triggering principal wraps the relevant zone
//! keys for the AI's ephemeral session pubkey and writes them into
//! the Job record. Validity is state-based: the wrap is unusable
//! once the Job lifecycle conditions no longer hold.
