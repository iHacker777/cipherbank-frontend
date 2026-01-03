import React from 'react';
import { Activity, Upload, FileText, Users, Key } from 'lucide-react';
import haptics from '../utils/ios-haptics';

/**
 * iOS 18 Bottom Tab Bar Component
 * Designed to match native iOS tab bar with proper blur, spacing, and animations
 * Only visible on mobile devices (< 1024px)
 */
const BottomTabBar = ({ currentView, setCurrentView, user }) => {
  const isAdmin = user?.roles?.includes('ROLE_ADMIN') || false;

  const handleTabClick = (viewId) => {
    if (currentView !== viewId) {
      haptics.selection();
      setCurrentView(viewId);
    }
  };

  const tabs = [
    {
      id: 'dashboard',
      label: 'Dashboard',
      icon: Activity,
      alwaysShow: true
    },
    {
      id: 'upload',
      label: 'Upload',
      icon: Upload,
      alwaysShow: true
    },
    {
      id: 'statements',
      label: 'Statements',
      icon: FileText,
      alwaysShow: true
    },
    {
      id: 'users',
      label: 'Users',
      icon: Users,
      alwaysShow: false,
      requiresAdmin: true
    },
    {
      id: 'changepassword',
      label: 'Settings',
      icon: Key,
      alwaysShow: !isAdmin // Show settings tab only if not admin (to keep 4 tabs max)
    }
  ];

  // Filter tabs based on permissions and display rules
  const visibleTabs = tabs.filter(tab => {
    if (!tab.alwaysShow && tab.requiresAdmin && !isAdmin) return false;
    if (!tab.alwaysShow && !tab.requiresAdmin) return tab.alwaysShow;
    return true;
  });

  // Ensure max 5 tabs (iOS best practice)
  const displayTabs = visibleTabs.slice(0, 5);

  return (
    <div className="ios-tab-bar mobile-only">
      <div className="ios-tab-bar-container">
        <div className="ios-tab-bar-content">
          {displayTabs.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => handleTabClick(id)}
              className={`ios-tab-item no-select ${currentView === id ? 'active' : ''}`}
              aria-label={label}
              aria-current={currentView === id ? 'page' : undefined}
            >
              <Icon />
              <span className="ios-tab-item-label">{label}</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
};

export default BottomTabBar;
