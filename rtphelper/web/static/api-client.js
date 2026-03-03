/**
 * Unified API client for backend communication.
 * 
 * Consolidates all fetch() calls and polling mechanisms.
 */

import { log, logError } from './utils.js';

/**
 * Base API request wrapper with error handling.
 */
async function request(method, endpoint, body = null) {
    const options = {
        method,
        headers: {
            'Content-Type': 'application/json',
        },
    };
    
    if (body) {
        options.body = JSON.stringify(body);
    }
    
    try {
        log('API', `${method} ${endpoint}`);
        const response = await fetch(endpoint, options);
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`HTTP ${response.status}: ${errorText}`);
        }
        
        return await response.json();
    } catch (err) {
        logError('API', `Request failed: ${method} ${endpoint}`, err);
        throw err;
    }
}

/**
 * API methods organized by category.
 */
export const api = {
    // Capture endpoints
    async startCapture(params) {
        return request('POST', '/capture/start', params);
    },
    
    async stopCapture() {
        return request('POST', '/capture/stop');
    },
    
    async getStatus() {
        return request('GET', '/capture/status');
    },
    
    async getProgress() {
        return request('GET', '/capture/progress');
    },
    
    // Configuration endpoints
    async getConfig() {
        return request('GET', '/config');
    },
    
    async getReachability(environment = null) {
        const endpoint = environment 
            ? `/reachability?environment=${encodeURIComponent(environment)}`
            : '/reachability';
        return request('GET', endpoint);
    },
    
    async refreshReachability(environment = null) {
        const endpoint = environment
            ? `/reachability/refresh?environment=${encodeURIComponent(environment)}`
            : '/reachability/refresh';
        return request('POST', endpoint);
    },
    
    // Correlation endpoints
    async submitCorrelation(params) {
        return request('POST', '/correlation/submit', params);
    },
    
    async listCorrelationJobs() {
        return request('GET', '/correlation/jobs');
    },
    
    async getCorrelationLogs(jobId, lines = 100) {
        return request('GET', `/correlation/jobs/${jobId}/logs?lines=${lines}`);
    },
    
    async downloadCorrelationFile(jobId, fileType) {
        const url = `/correlation/jobs/${jobId}/files/${fileType}`;
        window.open(url, '_blank');
    },
    
    // Session files endpoints
    async getSessionFiles(sessionId) {
        return request('GET', `/files/session/${sessionId}`);
    },
    
    // Storage flush endpoints
    async pauseStorageFlush(sessionId) {
        return request('POST', `/capture/${sessionId}/storage-flush/pause`);
    },
    
    async resumeStorageFlush(sessionId) {
        return request('POST', `/capture/${sessionId}/storage-flush/resume`);
    },
};

/**
 * Unified polling mechanism.
 */
export class Poller {
    constructor(fetchFn, callback, interval = 1000) {
        this.fetchFn = fetchFn;
        this.callback = callback;
        this.interval = interval;
        this.timerId = null;
        this.running = false;
    }
    
    start() {
        if (this.running) return;
        
        this.running = true;
        this._poll();
    }
    
    stop() {
        this.running = false;
        if (this.timerId) {
            clearTimeout(this.timerId);
            this.timerId = null;
        }
    }
    
    async _poll() {
        if (!this.running) return;
        
        try {
            const data = await this.fetchFn();
            this.callback(data);
        } catch (err) {
            logError('Poller', 'Poll failed:', err);
        }
        
        if (this.running) {
            this.timerId = setTimeout(() => this._poll(), this.interval);
        }
    }
}

/**
 * Create status poller.
 */
export function createStatusPoller(callback, interval = 1000) {
    return new Poller(api.getStatus, callback, interval);
}

/**
 * Create correlation jobs poller.
 */
export function createCorrelationJobsPoller(callback, interval = 2000) {
    return new Poller(api.listCorrelationJobs, callback, interval);
}

/**
 * Create correlation live logs poller.
 */
export function createCorrelationLogsPoller(jobId, callback, interval = 1000) {
    const fetchFn = () => api.getCorrelationLogs(jobId, 100);
    return new Poller(fetchFn, callback, interval);
}

/**
 * Download file by path.
 */
export function downloadFile(path) {
    const encodedPath = encodeURIComponent(path);
    window.open(`/download?path=${encodedPath}`, '_blank');
}

/**
 * Download S3 file by key.
 */
export function downloadS3File(key) {
    const encodedKey = encodeURIComponent(key);
    window.open(`/download/s3?key=${encodedKey}`, '_blank');
}

/**
 * Health check endpoint.
 */
export async function checkHealth() {
    try {
        const response = await fetch('/health');
        return response.ok;
    } catch (err) {
        return false;
    }
}
