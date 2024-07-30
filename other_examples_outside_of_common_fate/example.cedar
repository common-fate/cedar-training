permit (
    principal is MyApp::User,
    action == MyApp::Photos::Action::"Read",
    resource
)
when { principal.paid_billing_tier == true && resource.is_public == true };