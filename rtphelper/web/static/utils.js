/**
 * Shared utility functions.
 * 
 * Pure functions for formatting, validation, and DOM manipulation.
 */

/**
 * Format bytes to human-readable string.
 */
export function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    if (!bytes) return '-';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return (bytes / Math.pow(k, i)).toFixed(2) + ' ' + sizes[i];
}

/**
 * Format duration in seconds to human-readable string.
 */
export function formatDuration(seconds) {
    if (!seconds || seconds < 0) return '-';
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);
    
    if (hours > 0) {
        return `${hours}h ${minutes}m ${secs}s`;
    } else if (minutes > 0) {
        return `${minutes}m ${secs}s`;
    } else {
        return `${secs}s`;
    }
}

/**
 * Escape HTML to prevent XSS.
 */
export function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

/**
 * Parse comma/newline-separated Call-IDs.
 */
export function parseCallIds(text) {
    if (!text || !text.trim()) return [];
    return text
        .split(/[\n,]+/)
        .map(id => id.trim())
        .filter(id => id.length > 0);
}

/**
 * Parse comma/newline-separated IP addresses.
 */
export function parseIpList(text) {
    if (!text || !text.trim()) return [];
    return text
        .split(/[\n,\s]+/)
        .map(ip => ip.trim())
        .filter(ip => ip.length > 0);
}

/**
 * Debounce function calls.
 */
export function debounce(fn, delay) {
    let timeoutId = null;
    return function(...args) {
        clearTimeout(timeoutId);
        timeoutId = setTimeout(() => fn.apply(this, args), delay);
    };
}

/**
 * Throttle function calls.
 */
export function throttle(fn, delay) {
    let lastCall = 0;
    return function(...args) {
        const now = Date.now();
        if (now - lastCall >= delay) {
            lastCall = now;
            return fn.apply(this, args);
        }
    };
}

/**
 * Show toast notification.
 */
export function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    toast.style.cssText = `
        position: fixed;
        bottom: 20px;
        right: 20px;
        padding: 12px 20px;
        border-radius: 4px;
        background: ${type === 'error' ? '#e74c3c' : type === 'success' ? '#27ae60' : '#3498db'};
        color: white;
        font-weight: 500;
        z-index: 10000;
        animation: slideIn 0.3s ease-out;
    `;
    
    document.body.appendChild(toast);
    
    setTimeout(() => {
        toast.style.animation = 'slideOut 0.3s ease-out';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

/**
 * Log with category prefix.
 */
export function log(category, message, ...args) {
    console.log(`[${category}]`, message, ...args);
}

/**
 * Log error with category prefix.
 */
export function logError(category, message, ...args) {
    console.error(`[${category}]`, message, ...args);
}

/**
 * Validate Call-ID format.
 */
export function isValidCallId(callId) {
    return /^[a-zA-Z0-9@._-]+$/.test(callId);
}

/**
 * Validate IP address format.
 */
export function isValidIp(ip) {
    // Simple IPv4/IPv6 check
    const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    const ipv6Pattern = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    return ipv4Pattern.test(ip) || ipv6Pattern.test(ip);
}

/**
 * Format ISO timestamp to readable datetime.
 */
export function formatTimestamp(isoString) {
    if (!isoString) return '-';
    try {
        const date = new Date(isoString);
        return date.toLocaleString();
    } catch (err) {
        return isoString;
    }
}

/**
 * Get progress percentage.
 */
export function getProgressPercent(current, total) {
    if (!total || total === 0) return 0;
    return Math.min(100, Math.round((current / total) * 100));
}

/**
 * Generate unique ID.
 */
export function generateId() {
    return `id_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

/**
 * Deep clone object.
 */
export function deepClone(obj) {
    return JSON.parse(JSON.stringify(obj));
}

/**
 * Check if element is visible in viewport.
 */
export function isElementVisible(element) {
    const rect = element.getBoundingClientRect();
    return (
        rect.top >= 0 &&
        rect.left >= 0 &&
        rect.bottom <= (window.innerHeight || document.documentElement.clientHeight) &&
        rect.right <= (window.innerWidth || document.documentElement.clientWidth)
    );
}
