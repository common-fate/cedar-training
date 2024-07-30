@advice("Access is automatically approved because you are on-call")
permit (
    principal in PagerDuty::OnCall::All::"int_pd_123", // ANYONE on-call
    action == Access::Action::"Activate", // auto-approved access
    resource is AWS::IDC::AccountGrant
);