import { useT } from "../i18n/context";
import { stepIcons, stepTones, type Step } from "../lib/steps";
import { formatClock } from "../lib/time";
import { Icon } from "./Icon";
import { Pill } from "./Pill";
import "./StepTrail.scss";

// Les étapes cochées d'un geste long (R-GESTE-4), dans l'ordre où l'agent
// les rapporte. Le libellé est celui du catalogue pour la clé de l'étape :
// le terminal imprime le même par step.Print. Le détail, venu de l'agent,
// s'affiche en texte brut, en chasse fixe.
export function StepTrail({ steps }: { steps: readonly Step[] }) {
  const t = useT();
  return (
    <ol className="step-trail">
      {steps.map((step, position) => (
        <li key={position} className={`step-trail-item step-trail-${stepTones[step.state]}`}>
          <span className="step-trail-mark">
            <Icon name={stepIcons[step.state]} />
          </span>
          <span className="step-trail-label">{t(step.key)}</span>
          <Pill tone={stepTones[step.state]} small>
            {t(`step_trail.state_${step.state}`)}
          </Pill>
          <span className="step-trail-at mono muted">{formatClock(step.at)}</span>
          {step.detail ? <span className="step-trail-detail mono">{step.detail}</span> : null}
        </li>
      ))}
    </ol>
  );
}
