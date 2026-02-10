//! # Permissions Macro
//!
//! Procedural macros for automatic permission checking in Horizon handlers.
//! Supports the `#[with_permission(...)]` attribute for automatic permission validation.

use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input,
    Expr,
    Ident,
    ItemFn,
    Token,
};

/// Arguments for the with_permission macro
#[derive(Debug)]
enum PermissionMode {
    /// All specified permissions must be granted (AND logic)
    All(Vec<Expr>),
    /// At least one specified permission must be granted (OR logic)
    Any(Vec<Expr>),
}

impl Parse for PermissionMode {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        // Check if we have a mode specifier (all/any) followed by =
        if input.peek(Ident) && input.peek2(Token![=]) {
            let ident: Ident = input.parse()?;
            let mode_name = ident.to_string();
            input.parse::<Token![=]>()?; // consume the =

            match mode_name.as_str() {
                "all" => {
                    let permissions = parse_permission_list(input)?;
                    Ok(Self::All(permissions))
                },
                "any" => {
                    let permissions = parse_permission_list(input)?;
                    Ok(Self::Any(permissions))
                },
                _ => {
                    Err(syn::Error::new(
                        ident.span(),
                        "Expected 'all' or 'any' before '='",
                    ))
                },
            }
        }
        else {
            // No mode specifier, default to 'all' and parse permission list
            let permissions = parse_permission_list(input)?;
            Ok(Self::All(permissions))
        }
    }
}

/// Parses a comma-separated list of permission expressions from the token stream.
///
/// # Arguments
///
/// * `input` - The parse stream to read permission expressions from
///
/// # Returns
///
/// A vector of parsed `Expr` representing the permissions, or an error if parsing fails
fn parse_permission_list(input: ParseStream) -> syn::Result<Vec<Expr>> {
    let mut permissions = Vec::new();

    loop {
        if input.is_empty() {
            break;
        }

        let expr: Expr = input.parse()?;
        permissions.push(expr);

        if input.is_empty() {
            break;
        }

        input.parse::<Token![,]>()?;
    }

    if permissions.is_empty() {
        return Err(input.error("at least one permission is required"));
    }

    Ok(permissions)
}

/// Attribute macro for checking permissions on handler functions.
///
/// Automatically injects permission checking code into the handler.
/// Supports both ALL (AND) and ANY (OR) permission checking logic.
///
/// # Requirements
///
/// The handler function must have access to:
/// - `state: &AppState` - Contains the database connection for permission checks
/// - `user: MiddlewareUser` - Provides the user ID for permission lookups
///
/// # Arguments
///
/// Accepts strongly typed Permission enum variants:
/// - **Users**: `Permission::Users(UserAction::Create)`, etc.
/// - **Teams**: `Permission::Teams(TeamAction::Create)`, etc.
/// - **API Keys**: `Permission::ApiKeys(ApiKeyAction::Create)`, etc.
///
/// # Modes
///
/// - **all** (default): ALL permissions must be granted (AND logic)
/// - **any**: At least ONE permission must be granted (OR logic)
///
/// # Examples
///
/// ```ignore
/// use axum::Json;
/// use server::AppState;
/// use server::middleware::auth::MiddlewareUser;
/// use permissions_macro::with_permission;
/// use auth::permissions::{Permission, UserAction, TeamAction};
/// use error::Result;
///
/// // Default mode (all) - requires BOTH permissions
/// #[with_permission(Permission::Users(UserAction::Read), Permission::Teams(TeamAction::Read))]
/// pub async fn get_users_and_teams(
///     state: &AppState,
///     user: MiddlewareUser,
/// ) -> Result<Json<CombinedData>> {
///     // Both permissions required
///     Ok(Json(CombinedData::default()))
/// }
///
/// // Explicit 'all' mode - same as default
/// #[with_permission(all = Permission::Users(UserAction::Read), Permission::Teams(TeamAction::Read))]
/// pub async fn get_users_and_teams_explicit(
///     state: &AppState,
///     user: MiddlewareUser,
/// ) -> Result<Json<CombinedData>> {
///     // Both permissions required
///     Ok(Json(CombinedData::default()))
/// }
///
/// // 'any' mode - requires at least ONE permission
/// #[with_permission(any = Permission::Users(UserAction::Create), Permission::Teams(TeamAction::Create))]
/// pub async fn create_user_or_team(
///     state: &AppState,
///     user: MiddlewareUser,
/// ) -> Result<Json<CreationResult>> {
///     // Either users:create OR teams:create permission is sufficient
///     Ok(Json(CreationResult::default()))
/// }
/// ```
///
/// # Generated Code
///
/// The macro generates code that:
/// 1. Creates a list of required Permission enum variants
/// 2. Instantiates a PermissionService from state.db
/// 3. Checks permissions according to the specified mode (all/any)
/// 4. Returns an error if permission requirements are not met
///
/// # Compile-Time Validation
///
/// Permission expressions are validated at compile time. Using invalid Permission
/// enum variants will result in compilation errors.
#[proc_macro_attribute]
pub fn with_permission(args: TokenStream, input: TokenStream) -> TokenStream {
    let mode = parse_macro_input!(args as PermissionMode);
    let mut input_fn = parse_macro_input!(input as ItemFn);

    // Generate the permission check code based on mode
    let permission_check = match mode {
        PermissionMode::All(permissions) => generate_all_permission_check(&permissions),
        PermissionMode::Any(permissions) => generate_any_permission_check(&permissions),
    };

    // Wrap the function body with permission checking
    let original_block = input_fn.block;
    #[allow(
        clippy::expect_used,
        reason = "Generated code always parses correctly in procedural macro context"
    )]
    let new_block = syn::parse2(quote! {
        {
            #permission_check
            #original_block
        }
    })
    .expect("Failed to parse generated block");

    input_fn.block = Box::new(new_block);

    quote!(#input_fn).into()
}

/// Generate permission checking code for ALL mode (AND logic)
fn generate_all_permission_check(permissions: &[Expr]) -> proc_macro2::TokenStream {
    let permission_exprs = permissions.iter().map(|expr| quote! { #expr });

    quote! {
        // Verify required variables are in scope: state (AppState), user (MiddlewareUser)
        // This code requires the handler to have access to:
        // - state: &AppState (contains db connection)
        // - user: MiddlewareUser (contains user.id and roles from JWT)

        let required_permissions = vec![
            #(#permission_exprs),*
        ];

        // Create permission service
        let permission_service = auth::permissions::PermissionService::new(state.db.clone());

        // Check ALL required permissions - all must be granted (AND logic)
        for perm in &required_permissions {
            match permission_service.check_permission_with_jwt_roles(&user.id, perm.clone(), &user.roles).await {
                Ok(auth::permissions::PermissionCheckResult::Allowed) => {
                    // Permission granted, continue
                },
                Ok(auth::permissions::PermissionCheckResult::Denied) => {
                    return Err(error::AppError::forbidden(
                        format!("Missing required permission: {:?}", perm)
                    ));
                },
                Ok(auth::permissions::PermissionCheckResult::RequiresContext { .. }) => {
                    return Err(error::AppError::forbidden(
                        format!("Permission requires additional context: {:?}", perm)
                    ));
                },
                Ok(auth::permissions::PermissionCheckResult::Unauthenticated) => {
                    return Err(error::AppError::unauthorized("User not authenticated"));
                },
                Err(e) => {
                    // Database error, fail closed
                    tracing::error!("Failed to check permission: {}", e);
                    return Err(error::AppError::internal("Permission check failed"));
                },
            }
        }
    }
}

/// Generate permission checking code for ANY mode (OR logic)
fn generate_any_permission_check(permissions: &[Expr]) -> proc_macro2::TokenStream {
    let permission_exprs = permissions.iter().map(|expr| quote! { #expr });

    quote! {
        // Verify required variables are in scope: state (AppState), user (MiddlewareUser)
        // This code requires the handler to have access to:
        // - state: &AppState (contains db connection)
        // - user: MiddlewareUser (contains user.id and roles from JWT)

        let required_permissions = vec![
            #(#permission_exprs),*
        ];

        // Check ANY required permission - at least one must be granted (OR logic)
        let mut has_permission = false;
        let mut denied_permissions = Vec::new();

        // Create permission service
        let permission_service = auth::permissions::PermissionService::new(state.db.clone());

        for perm in &required_permissions {
            match permission_service.check_permission_with_jwt_roles(&user.id, perm.clone(), &user.roles).await {
                Ok(auth::permissions::PermissionCheckResult::Allowed) => {
                    has_permission = true;
                    break; // Found one allowed permission, we're done
                },
                Ok(auth::permissions::PermissionCheckResult::Denied) => {
                    denied_permissions.push(format!("{:?}", perm));
                },
                Ok(auth::permissions::PermissionCheckResult::RequiresContext { .. }) => {
                    denied_permissions.push(format!("{:?} (requires context)", perm));
                },
                Ok(auth::permissions::PermissionCheckResult::Unauthenticated) => {
                    return Err(error::AppError::unauthorized("User not authenticated"));
                },
                Err(e) => {
                    // Database error, fail closed
                    tracing::error!("Failed to check permission: {}", e);
                    return Err(error::AppError::internal("Permission check failed"));
                },
            }
        }

        if !has_permission {
            return Err(error::AppError::forbidden(
                format!("Missing required permissions. Need at least one of: {}", denied_permissions.join(", "))
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use syn::parse_str;

    use super::*;

    #[test]
    fn test_parse_all_mode() {
        let input = "Permission::Users(UserAction::Read), Permission::Teams(TeamAction::Create)";
        let mode: PermissionMode = parse_str(input).unwrap();

        match mode {
            PermissionMode::All(perms) => assert_eq!(perms.len(), 2),
            PermissionMode::Any(_) => panic!("Expected All mode"),
        }
    }

    #[test]
    fn test_parse_any_mode() {
        let input = "any = Permission::Users(UserAction::Read), Permission::Teams(TeamAction::Create)";
        let mode: PermissionMode = parse_str(input).unwrap();

        match mode {
            PermissionMode::All(_) => panic!("Expected Any mode"),
            PermissionMode::Any(perms) => assert_eq!(perms.len(), 2),
        }
    }

    #[test]
    fn test_parse_default_all_mode() {
        let input = "Permission::Users(UserAction::Read)";
        let mode: PermissionMode = parse_str(input).unwrap();

        match mode {
            PermissionMode::All(perms) => assert_eq!(perms.len(), 1),
            PermissionMode::Any(_) => panic!("Expected All mode"),
        }
    }

    #[test]
    fn test_parse_empty_permissions_error() {
        let input = "";
        let result: syn::Result<PermissionMode> = parse_str(input);
        assert!(result.is_err());
    }
}
