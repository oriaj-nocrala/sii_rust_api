use serde::{Serialize, Deserialize};

use crate::dte::dte::Signature;

#[derive(Serialize, Deserialize)]
pub struct GetTokenRequest {
  pub header: String,
  pub item: Item,
  pub signature: Signature
}

#[derive(Serialize, Deserialize)]
pub struct Item {
  #[serde(rename = "Semilla")]
  pub seed: String
}