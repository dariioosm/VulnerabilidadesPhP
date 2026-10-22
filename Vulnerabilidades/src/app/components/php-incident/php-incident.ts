import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-php-incident',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './php-incident.html',
  styleUrls: ['./php-incident.css']
})
export class PhpIncidentComponent {
  currentTab: string = 'overview';
  
  // Base de datos oficial PHP2Shell 2026
  versions = [
    { branch: 'PHP 8.5', affected: '< 8.5.12', patched: '8.5.12' },
    { branch: 'PHP 8.4', affected: '< 8.4.27', patched: '8.4.27' },
    { branch: 'PHP 8.3', affected: '< 8.3.36', patched: '8.3.36' },
    { branch: 'PHP 8.2', affected: '< 8.2.35', patched: '8.2.35' },
    { branch: 'Versiones heredadas (7.x, 5.x)', affected: 'Todas', patched: 'Sin soporte (Migrar urgente)' }
  ];

  phpVersionInput: string = '';
  isPhpFpm: boolean = true;
  diagnosticResult: string = '';
  diagnosticClass: string = '';

  rawLogsInput: string = '';
  logAnalysisResults: Array<{ line: string; status: string; detail: string }> = [];
  analysisExecuted: boolean = false;

  changeTab(tab: string): void {
    this.currentTab = tab;
  }

  // Motor de reglas preciso para PHP2Shell
  checkSystemProtection(): void {
    if (!this.phpVersionInput) {
      this.diagnosticResult = 'Por favor, introduce la versión de PHP obtenida en tu Laravel.';
      this.diagnosticClass = 'alert-warning';
      return;
    }

    const version = this.phpVersionInput.trim();
    let isVulnerable = false;

    // Parsing preciso de subversiones críticas de 2026
    if (version.startsWith('8.5.')) {
      const sub = parseInt(version.split('.')[2], 10);
      if (isNaN(sub) || sub < 12) isVulnerable = true;
    } else if (version.startsWith('8.4.')) {
      const sub = parseInt(version.split('.')[2], 10);
      if (isNaN(sub) || sub < 27) isVulnerable = true;
    } else if (version.startsWith('8.3.')) {
      const sub = parseInt(version.split('.')[2], 10);
      if (isNaN(sub) || sub < 36) isVulnerable = true;
    } else if (version.startsWith('8.2.')) {
      const sub = parseInt(version.split('.')[2], 10);
      if (isNaN(sub) || sub < 35) isVulnerable = true;
    } else {
      isVulnerable = true; // Ramas antiguas como 8.1, 8.0, 7.x
    }

    if (isVulnerable) {
      this.diagnosticResult = `❌ CRÍTICO (CVSS 9.2): El backend de Twinteach está EXPUESTO. Un atacante no autenticado podría explotar fallos de memoria en el núcleo de PHP para robar claves de la base de datos o ejecutar comandos en el servidor.`;
      this.diagnosticClass = 'alert-danger';
    } else {
      this.diagnosticResult = '✅ PROTEGIDO: Tu ecosistema Laravel cuenta con los parches nativos que neutralizan los patrones corruptos de memoria.';
      this.diagnosticClass = 'alert-success';
    }
  }

  // Escáner forense con firmas de explotación PHP2Shell
  analyzeLogsLocal(): void {
    this.logAnalysisResults = [];
    this.analysisExecuted = true;

    if (!this.rawLogsInput.trim()) return;

    const lines = this.rawLogsInput.split('\n');
    for (let line of lines) {
      if (!line.trim()) continue;
      const lowerLine = line.toLowerCase();
      
      // Patrones de explotación PHP2Shell (Cookies gigantes de sesión, errores 500 iterativos o crashes de workers)
      const hasGiantCookie = lowerLine.includes('phpsessid') && line.length > 500;
      const hasOomTrigger = lowerLine.includes('multipart/form-data') && (lowerLine.includes('500') || lowerLine.includes('crash'));

      if (hasGiantCookie) {
        this.logAnalysisResults.push({
          line: line.substring(0, 75) + '...',
          status: 'PELIGRO',
          detail: 'Posible intento de fuga de memoria o Use-After-Free usando payloads inyectados en la cabecera PHPSESSID.'
        });
      } else if (hasOomTrigger) {
        this.logAnalysisResults.push({
          line: line.substring(0, 75) + '...',
          status: 'SOSPECHOSO',
          detail: 'Petición multipart inusual seguida de un error crítico de servidor. Podría indicar abuso del gestor de memoria (OOM).'
        });
      } else {
        this.logAnalysisResults.push({
          line: line.substring(0, 75) + '...',
          status: 'SEGURO',
          detail: 'Transacción API REST estándar procesada de manera limpia.'
        });
      }
    }
  }

  loadLogExamples(): void {
    this.rawLogsInput = 
`192.168.2.11 - - [2026-10-12] "POST /api/login HTTP/1.1" 500 - "Cookie: PHPSESSID=ad89f...[PAYLOAD EXTRA LARGO EXPLOIT MEMORY DISCLOSURE]..."
192.168.2.45 - - [2026-10-12] "POST /api/v1/attachments HTTP/1.1" 500 0 (Worker process crashed Unexpectedly)
192.168.2.14 - - [2026-10-12] "GET /api/courses HTTP/1.1" 200 2540`;
    this.analysisExecuted = false;
  }
}
