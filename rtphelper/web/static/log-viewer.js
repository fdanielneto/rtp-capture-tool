/**
 * Log Viewer Module
 * Handles log display, streaming, and filtering
 */

export class LogViewer {
  constructor(api, utils) {
    this.api = api;
    this.utils = utils;
    
    // DOM references
    this.logSection = document.getElementById('logSection');
    this.appLog = document.getElementById('appLog');
    this.showLogsToggle = document.getElementById('showLogsToggle');
    this.downloadLogBtn = document.getElementById('downloadLogBtn');
    this.clearLogBtn = document.getElementById('clearLogBtn');
    
    // State
    this.logVisible = false;
    this.maxLogLines = 500;
    this.logLines = [];
    this.eventSource = null;
    
    this.bindEvents();
  }
  
  bindEvents() {
    if (this.showLogsToggle) {
      this.showLogsToggle.addEventListener('click', () => this.toggleLogs());
    }
    if (this.downloadLogBtn) {
      this.downloadLogBtn.addEventListener('click', () => this.downloadLog());
    }
    if (this.clearLogBtn) {
      this.clearLogBtn.addEventListener('click', () => this.clearLog());
    }
  }
  
  toggleLogs() {
    this.logVisible = !this.logVisible;
    
    if (this.logSection) {
      this.logSection.style.display = this.logVisible ? 'block' : 'none';
    }
    if (this.showLogsToggle) {
      this.showLogsToggle.textContent = this.logVisible ? 'Hide Logs' : 'Show Logs';
    }
  }
  
  appendLog(text, category = 'INFO') {
    if (!this.appLog) return;
    
    const timestamp = new Date().toLocaleTimeString('en-US', { hour12: false });
    const line = `[${timestamp}] [${category}] ${text}`;
    
    this.logLines.push(line);
    
    // Keep only last N lines
    if (this.logLines.length > this.maxLogLines) {
      this.logLines = this.logLines.slice(-this.maxLogLines);
      this.appLog.innerHTML = '';
    }
    
    const lineDiv = document.createElement('div');
    lineDiv.className = 'log-line';
    lineDiv.textContent = line;
    
    // Color coding
    if (category === 'ERROR' || category === 'ERRORS') {
      lineDiv.style.color = '#ff6b6b';
    } else if (category === 'WARN' || category === 'WARNING') {
      lineDiv.style.color = '#ffd666';
    } else if (category === 'SUCCESS') {
      lineDiv.style.color = '#51cf66';
    }
    
    this.appLog.appendChild(lineDiv);
    this.appLog.scrollTop = this.appLog.scrollHeight;
  }
  
  clearLog() {
    this.logLines = [];
    if (this.appLog) {
      this.appLog.innerHTML = '';
    }
    this.appendLog('Logs cleared', 'INFO');
  }
  
  async downloadLog() {
    try {
      const blob = new Blob([this.logLines.join('\n')], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `rtp-capture-log-${new Date().toISOString().replace(/[:.]/g, '-')}.txt`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      
      this.utils.showToast('Log downloaded', 'success');
    } catch (error) {
      console.error('Download log failed:', error);
      this.utils.showToast('Failed to download log', 'error');
    }
  }
  
  startLogStreaming() {
    if (this.eventSource) {
      return; // Already streaming
    }
    
    this.eventSource = new EventSource('/api/logs/stream');
    
    this.eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        this.appendLog(data.message || data.text, data.category || 'INFO');
      } catch (error) {
        console.error('Failed to parse log event:', error);
      }
    };
    
    this.eventSource.onerror = (error) => {
      console.error('Log stream error:', error);
      this.stopLogStreaming();
      // Auto-reconnect after 5 seconds
      setTimeout(() => this.startLogStreaming(), 5000);
    };
  }
  
  stopLogStreaming() {
    if (this.eventSource) {
      this.eventSource.close();
      this.eventSource = null;
    }
  }
  
  // Convenience method for external use
  log(text, category = 'INFO') {
    this.appendLog(text, category);
  }
}
