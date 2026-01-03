/**
 * iOS Haptics Utility
 * Provides haptic feedback for iOS webapps
 */

class iOSHaptics {
  constructor() {
    this.isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent) && !window.MSStream;
    this.supportsVibrate = 'vibrate' in navigator;
  }

  /**
   * Trigger haptic feedback
   * @param {string} type - Type of haptic: 'light', 'medium', 'heavy', 'success', 'warning', 'error', 'selection'
   */
  trigger(type = 'light') {
    if (this.supportsVibrate) {
      this._triggerVibration(type);
    }
  }

  /**
   * Trigger vibration using Vibration API
   * @param {string} type - Type of haptic feedback
   * @private
   */
  _triggerVibration(type) {
    const patterns = {
      light: 10,
      medium: 20,
      heavy: 40,
      success: [10, 50, 10],
      warning: [20, 100, 20],
      error: [40, 100, 40, 100, 40],
      selection: 5
    };

    const pattern = patterns[type] || patterns.light;
    
    try {
      navigator.vibrate(pattern);
    } catch (e) {
      // Silently fail
    }
  }

  // Convenience methods
  light() { this.trigger('light'); }
  medium() { this.trigger('medium'); }
  heavy() { this.trigger('heavy'); }
  success() { this.trigger('success'); }
  warning() { this.trigger('warning'); }
  error() { this.trigger('error'); }
  selection() { this.trigger('selection'); }
}

// Create singleton instance
const haptics = new iOSHaptics();

export default haptics;
