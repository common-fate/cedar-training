@advice("Access is automatically approved because you are on-call")
permit (
    principal in
        PagerDuty::OnCall::"PNE4HSJ", // On-call members for Demo Schedule
    action == Access::Action::"Activate", // auto-approved access
    resource is AWS::IDC::AccountGrant
);