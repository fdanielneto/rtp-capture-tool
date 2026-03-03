/**
 * Centralized application state management.
 * 
 * Replaces 130+ global variables with single state container.
 * Provides reactive updates via subscription mechanism.
 */

export class AppState {
    constructor() {
        this._state = {
            // Session state
            sessionId: null,
            running: false,
            mode: null,
            
            // UI selection state
            selectedEnvironment: null,
            selectedRegion: null,
            selectedSubRegion: null,
            selectedHosts: [],
            allHostsMode: false,
            
            // Capture parameters
            callIds: '',
            ipListALeg: '',
            ipListBLeg: '',
            captureIpList: '',
            storageMode: 'local+s3',
            durationMinutes: 5,
            
            // Status data
            statusData: null,
            captureProgress: null,
            
            // File lists
            rawFiles: [],
            uploadsList: [],
            combinedFiles: [],
            decryptedFiles: [],
            
            // Configuration
            environments: {},
            reachableHosts: {},
            unreachableHosts: {},
            
            // Correlation state
            correlationJobs: [],
            selectedJobId: null,
            correlationLiveLogs: [],
            
            // Polling timers (for cleanup)
            statusTimer: null,
            logPollTimer: null,
            correlationLiveLogTimer: null,
            reachabilityRetryTimer: null,
        };
        
        this._subscribers = {};
    }
    
    /**
     * Get state value by key.
     */
    get(key) {
        return this._state[key];
    }
    
    /**
     * Set state value and notify subscribers.
     */
    set(key, value) {
        const oldValue = this._state[key];
        this._state[key] = value;
        
        if (oldValue !== value) {
            this._notify(key, value, oldValue);
        }
    }
    
    /**
     * Update multiple state keys at once.
     */
    update(updates) {
        Object.entries(updates).forEach(([key, value]) => {
            this.set(key, value);
        });
    }
    
    /**
     * Subscribe to state changes for a specific key.
     * 
     * @param {string} key - State key to watch
     * @param {function} callback - Called with (newValue, oldValue)
     * @returns {function} Unsubscribe function
     */
    subscribe(key, callback) {
        if (!this._subscribers[key]) {
            this._subscribers[key] = [];
        }
        this._subscribers[key].push(callback);
        
        // Return unsubscribe function
        return () => {
            this._subscribers[key] = this._subscribers[key].filter(cb => cb !== callback);
        };
    }
    
    /**
     * Reset state to initial values (e.g., after capture stop).
     */
    reset(keys = null) {
        const keysToReset = keys || [
            'sessionId',
            'running',
            'mode',
            'statusData',
            'captureProgress',
            'rawFiles',
            'uploadsList',
            'correlationLiveLogs',
        ];
        
        keysToReset.forEach(key => {
            this.set(key, null);
        });
    }
    
    /**
     * Get full state snapshot (for debugging).
     */
    getSnapshot() {
        return { ...this._state };
    }
    
    /**
     * Clear all polling timers.
     */
    clearTimers() {
        ['statusTimer', 'logPollTimer', 'correlationLiveLogTimer', 'reachabilityRetryTimer'].forEach(key => {
            const timer = this.get(key);
            if (timer) {
                clearInterval(timer);
                this.set(key, null);
            }
        });
    }
    
    // Private methods
    
    _notify(key, newValue, oldValue) {
        const subscribers = this._subscribers[key] || [];
        subscribers.forEach(callback => {
            try {
                callback(newValue, oldValue);
            } catch (err) {
                console.error(`[AppState] Subscriber error for key "${key}":`, err);
            }
        });
    }
}

// Create singleton instance
export const state = new AppState();
