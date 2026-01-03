/**
 * iOS Haptics Utility for Safari 17.4+
 * Provides haptic feedback for iOS webapps using checkbox switch method
 * Falls back to Vibration API on supported devices
 */

class iOSHaptics {
  constructor() {
    this.isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent) && !window.MSStream;
    this.supportsVibrate = 'vibrate' in navigator;
    this.supportsSwitchHaptic = this.isIOS && this.checkSwitchSupport();
  }

  /**
   * Check if Safari supports switch attribute for checkbox (iOS 17.4+)
   */
  checkSwitchSupport() {
    try {
      const testInput = document.createElement('input');
      testInput.type = 'checkbox';
      testInput.setAttribute('switch', '');
      return testInput.getAttribute('switch') !== null;
    } catch (e) {
      return false;
    }
  }

  /**
   * Trigger haptic feedback
   * @param {string} type - Type of haptic: 'light', 'medium', 'heavy', 'success', 'warning', 'error'
   */
  trigger(type = 'light') {
    if (this.isIOS && this.supportsSwitchHaptic) {
      this._triggerIOSHaptic();
    } else if (this.supportsVibrate) {
      this._triggerVibration(type);
    }
  }

  /**
   * Trigger iOS haptic using switch checkbox method
   * @private
   */
  _triggerIOSHaptic() {
    try {
      // Create hidden checkbox with switch attribute
      const checkbox = document.createElement('input');
      checkbox.type = 'checkbox';
      checkbox.setAttribute('switch', '');
      checkbox.style.position = 'absolute';
      checkbox.style.opacity = '0';
      checkbox.style.pointerEvents = 'none';
      
      const label = document.createElement('label');
      label.style.position = 'absolute';
      label.style.opacity = '0';
      label.style.pointerEvents = 'none';
      
      document.body.appendChild(checkbox);
      document.body.appendChild(label);
      label.appendChild(checkbox);

      // Trigger the haptic by clicking the label
      requestAnimationFrame(() => {
        label.click();
        
        // Clean up after a short delay
        setTimeout(() => {
          document.body.removeChild(label);
        }, 100);
      });
    } catch (e) {
      console.warn('iOS haptic trigger failed:', e);
    }
  }

  /**
   * Trigger vibration using Vibration API (Android, etc.)
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
      console.warn('Vibration API failed:', e);
    }
  }

  /**
   * Predefined haptic patterns
   */
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
