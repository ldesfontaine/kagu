import { useState } from "react";

import { emptyCredentialsForm, passwordFormError } from "../lib/auth";
import { useForm } from "./useForm";

type PasswordFormValues = typeof emptyCredentialsForm;

// Le geste commun aux formulaires de mot de passe : les valeurs, l'erreur de
// la règle, et l'envoi qui ne part que si la règle passe. La longueur minimale
// vient du serveur : elle arrive en paramètre.
export function usePasswordForm(minLength: number, onValid: (values: PasswordFormValues) => void) {
  const { values, change } = useForm(emptyCredentialsForm);
  const [error, setError] = useState<string | null>(null);
  const submit = () => setError(submitPasswordForm(values, minLength, onValid));
  return { values, change, error, submit };
}

// Rend le refus (clé du catalogue) ; sans refus, appelle onValid une fois.
export function submitPasswordForm(values: PasswordFormValues, minLength: number, onValid: (values: PasswordFormValues) => void): string | null {
  const refusal = passwordFormError(values.password, values.confirmation, minLength);
  if (refusal === null) {
    onValid(values);
  }
  return refusal;
}
