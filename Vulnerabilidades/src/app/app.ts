import { Component, signal } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { PhpIncidentComponent } from './components/php-incident/php-incident';

@Component({
  imports: [RouterOutlet, PhpIncidentComponent],
  selector: 'app-root',
  styleUrl: './app.css',
  templateUrl: './app.html',
})
export class App {
  protected readonly title = signal('Vulnerabilidades');
}
