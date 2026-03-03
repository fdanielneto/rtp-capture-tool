/**
 * Capture Controls Module
 * Handles start/stop capture buttons and capture session state
 */

export class CaptureControls {
  constructor(api, state, utils) {
    this.api = api;
    this.state = state;
    this.utils = utils;
    
    // DOM references
    this.startBtn = document.getElementById('startBtn');
    this.stopBtn = document.getElementById('stopBtn');
    this.restartCaptureBtn = document.getElementById('restartCaptureBtn');
    this.cleanBtn = document.getElementById('cleanBtn');
    this.outputDirNameInput = document.getElementById('outputDirName');
    this.timeoutMinutesInput = document.getElementById('timeoutMinutes');
    
    this.bindEvents();
  }
  
  bindEvents() {
    if (this.startBtn) {
      this.startBtn.addEventListener('click', () => this.handleStartCapture());
    }
    if (this.stopBtn) {
      this.stopBtn.addEventListener('click', () => this.handleStopCapture());
    }
    if (this.restartCaptureBtn) {
      this.restartCaptureBtn.addEventListener('click', () => this.handleRestartCapture());
    }
    if (this.cleanBtn) {
      this.cleanBtn.addEventListener('click', () => this.handleCleanForm());
    }
    
    // Subscribe to capture state changes
    this.state.subscribe('isCapturing', (isCapturing) => this.updateButtonStates(isCapturing));
  }
  
  async handleStartCapture() {
    const environment = this.state.get('environment');
    const region = this.state.get('region');
    const subRegions = this.state.get('selectedSubRegions') || [];
    const hostIds = this.state.get('selectedHostIds') || [];
    const filter = this.state.get('bpfFilter') || 'udp';
    const outputDirName = this.outputDirNameInput?.value.trim() || '';
    const timeoutMinutes = parseInt(this.timeoutMinutesInput?.value || '0', 10) || null;
    const storageLocation = this.state.get('storageLocation') || 'local';
    const s3SpoolDir = this.state.get('s3SpoolDir') || '';
    
    if (!environment || !region) {
      this.utils.showToast('Please select environment and region', 'error');
      return;
    }
    
    try {
      this.startBtn.disabled = true;
      this.startBtn.textContent = 'Starting...';
      
      const response = await this.api.startCapture({
        environment,
        region,
        sub_regions: subRegions.length > 0 ? subRegions : null,
        host_ids: hostIds.length > 0 ? hostIds : null,
        filter,
        output_dir_name: outputDirName || null,
        timeout_minutes: timeoutMinutes,
        storage_location: storageLocation,
        s3_spool_dir: s3SpoolDir || null,
      });
      
      this.state.set('sessionId', response.session_id);
      this.state.set('isCapturing', true);
      this.utils.showToast('Capture started successfully', 'success');
      
    } catch (error) {
      console.error('Start capture failed:', error);
      this.utils.showToast(`Start capture failed: ${error.message}`, 'error');
      this.startBtn.disabled = false;
      this.startBtn.textContent = 'Start Capture';
    }
  }
  
  async handleStopCapture() {
    try {
      this.stopBtn.disabled = true;
      this.stopBtn.textContent = 'Stopping...';
      
      await this.api.stopCapture();
      
      this.state.set('isCapturing', false);
      this.utils.showToast('Capture stopped successfully', 'success');
      
    } catch (error) {
      console.error('Stop capture failed:', error);
      this.utils.showToast(`Stop capture failed: ${error.message}`, 'error');
      this.stopBtn.disabled = false;
      this.stopBtn.textContent = 'Stop Capture';
    }
  }
  
  async handleRestartCapture() {
    const sessionId = this.state.get('sessionId');
    if (!sessionId) {
      this.utils.showToast('No session to restart', 'error');
      return;
    }
    
    try {
      this.restartCaptureBtn.disabled = true;
      const response = await this.api.startCapture({
        resume_session_id: sessionId,
      });
      
      this.state.set('sessionId', response.session_id);
      this.state.set('isCapturing', true);
      this.utils.showToast('Capture restarted successfully', 'success');
      
    } catch (error) {
      console.error('Restart capture failed:', error);
      this.utils.showToast(`Restart capture failed: ${error.message}`, 'error');
      this.restartCaptureBtn.disabled = false;
    }
  }
  
  handleCleanForm() {
    // Reset form inputs
    if (this.outputDirNameInput) this.outputDirNameInput.value = '';
    if (this.timeoutMinutesInput) this.timeoutMinutesInput.value = '';
    
    // Clear state
    this.state.set('selectedSubRegions', []);
    this.state.set('selectedHostIds', []);
    this.state.set('bpfFilter', 'udp');
    
    this.utils.showToast('Form cleared', 'info');
  }
  
  updateButtonStates(isCapturing) {
    if (this.startBtn) {
      this.startBtn.disabled = isCapturing;
      this.startBtn.textContent = isCapturing ? 'Capturing...' : 'Start Capture';
    }
    if (this.stopBtn) {
      this.stopBtn.disabled = !isCapturing;
      this.stopBtn.textContent = 'Stop Capture';
    }
    if (this.restartCaptureBtn) {
      this.restartCaptureBtn.style.display = isCapturing ? 'none' : 'inline-block';
    }
  }
}
