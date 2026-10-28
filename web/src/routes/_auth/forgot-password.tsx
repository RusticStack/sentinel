// No email reset: a reset link would make the mailbox a second password for every account, including administrators'.
import { createFileRoute } from "@tanstack/react-router";
import { TextLink } from "../../components/ui.tsx";
import { AuthCard, AuthTitle } from "./-card.tsx";

const RECOVERY = `sqlite3 <PATH>/metadata.sqlite "SELECT username FROM local_credentials JOIN users ON users.id = local_credentials.user_id WHERE users.email = '<EMAIL>'"
sentinel admin recover --data-dir <PATH> --username <USERNAME>`;

export const Route = createFileRoute("/_auth/forgot-password")({
  head: () => ({ meta: [{ title: "Forgot your password · Sentinel" }] }),
  component: ForgotPassword,
});

function ForgotPassword() {
  return (
    <AuthCard className="max-w-md" header={<AuthTitle>Forgot your password?</AuthTitle>}
      footer={<p className="text-center text-sm"><TextLink to="/login" className="font-medium">Back to sign-in</TextLink></p>}>
      <div className="space-y-3 text-sm">
        <p>This instance does not reset passwords by email. Ask your Sentinel administrator: they can set a new password for your account on the server, which also signs out every session of it.</p>
        <details className="rounded-md border border-line p-3">
          <summary className="cursor-pointer font-medium text-strong">For the administrator</summary>
          <p className="mt-2">On the controller host, as the service user:</p>
          <p className="mt-2">Give the administrator your registered email address. For an email-registered account, the username is generated; find it by email in the metadata database before running recovery.</p>
          <pre className="mt-2 overflow-x-auto rounded bg-elevated p-2 text-xs text-strong"><code>{RECOVERY}</code></pre>
          <p className="mt-2 text-muted">It resets the password, clears sign-in and second-factor lockouts and revokes the account's sessions.</p>
        </details>
        <p className="text-muted">Never got the email that confirms your address? <TextLink to="/verify-email" className="underline">Ask for a new link</TextLink>.</p>
      </div>
    </AuthCard>
  );
}
