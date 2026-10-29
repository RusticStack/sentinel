// Open, invitation-only or approval-based sign-up is the controller's policy; the form only shows its refusals.
import { useEffect, useRef, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { CheckEmail } from "../../components/CheckEmail.tsx";
import { SignUpForm, type SignUpResult } from "../../components/SignUpForm.tsx";
import { TextLink } from "../../components/ui.tsx";
import { AuthCard, AuthTitle } from "./-card.tsx";

export const Route = createFileRoute("/_auth/register")({
  head: () => ({ meta: [{ title: "Create an account · Sentinel" }] }),
  component: Register,
});

function Register() {
  const [sent, setSent] = useState<SignUpResult | null>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => { if (sent) heading.current?.focus(); }, [sent]);

  return (
    <AuthCard className="max-w-md" header={<AuthTitle ref={heading} focusable>{sent ? "Confirm your address" : "Create an account"}</AuthTitle>}
      footer={<p className="text-center text-sm">Already have an account? <TextLink to="/login" className="font-medium">Sign in</TextLink></p>}>
      {sent ? <CheckEmail email={sent.email} verification={sent.verification} /> : <SignUpForm onAccepted={setSent} />}
    </AuthCard>
  );
}
