use crate::handlers::not_implemented;
use axum::response::Response;

pub async fn system_df() -> Response {
    not_implemented("system df is not implemented yet")
}
