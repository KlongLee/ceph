import { Component, Input } from '@angular/core';
import { Icons } from '../../enum/icons.enum';

@Component({
  selector: 'cd-progress',
  templateUrl: './progress.component.html',
  styleUrls: ['./progress.component.scss']
})
export class ProgressComponent {
  icons = Icons;
  @Input() progress: number;
  @Input() description: string;
  @Input() inProgress: boolean;
  @Input() executingTaskName: string;
  @Input() currentStep: string; // For upgradeStatus.which
  @Input() stepsCompleted: string;
  @Input() stepsAction: string;
  @Input() progressText: string; // For upgradeStatus.progress
  @Input() message: string; // For upgradeStatus.message
  @Input() isPaused: boolean;
}
