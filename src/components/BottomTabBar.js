import React from 'react';
import { Activity, Upload, FileText, Users, Key } from 'lucide-react';
import haptics from '../utils/ios-haptics';

/**
 * iOS 26 Floating Tab Bar Component
 * Only visible on mobile devices (< 1024px)
 *
 * FIXED: Updated class names to match CSS (tab-bar__container, tab-bar__item)
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
    { id: 'dashboard', label: 'Dashboard', icon: Activity },
    { id: 'upload', label: 'Upload', icon: Upload },
    { id: 'statements', label: 'Statements', icon: FileText },
    ...(isAdmin ? [{ id: 'users', label: 'Users', icon: Users }] : []),
    { id: 'changepassword', label: 'Settings', icon: Key },
  ];

  // Limit to 5 tabs max
  const displayTabs = tabs.slice(0, 5);

  return (
    <nav className="tab-bar" role="navigation" aria-label="Main navigation">
      <div className="tab-bar__container">
        <div className="tab-bar__content">
          {displayTabs.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => handleTabClick(id)}
              className={`tab-bar__item ${currentView === id ? 'tab-bar__item--active' : ''}`}
              aria-label={label}
              aria-current={currentView === id ? 'page' : undefined}
              type="button"
            >
              <Icon className="tab-bar__icon" />
              <span className="tab-bar__label">{label}</span>
            </button>
          ))}
        </div>
      </div>
    </nav>
  );
};

export default BottomTabBar;