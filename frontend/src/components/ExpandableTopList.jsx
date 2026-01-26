import { useState } from 'react';
import { ChevronDown, ChevronRight } from 'lucide-react';

const ExpandableTopList = ({ title, items, maxItems = 5, labelKey = 'site' }) => {
  const [expandedItems, setExpandedItems] = useState({});
  const displayItems = items.slice(0, maxItems);
  const maxCount = displayItems.length > 0 ? displayItems[0].count : 0;

  const toggleExpand = (index) => {
    setExpandedItems(prev => ({
      ...prev,
      [index]: !prev[index]
    }));
  };

  return (
    <div className="top-list expandable-top-list">
      <h3>{title}</h3>
      <div className="top-list-items">
        {displayItems.length === 0 ? (
          <div className="no-data">No data yet</div>
        ) : (
          displayItems.map((item, index) => {
            const name = item[labelKey] || item.site || item.category;
            const count = item.count;
            const sources = item.sources || [];
            const isExpanded = expandedItems[index];
            const hasSources = sources.length > 0;

            return (
              <div key={index} className="expandable-item">
                <div
                  className={`top-list-item ${hasSources ? 'clickable' : ''}`}
                  onClick={() => hasSources && toggleExpand(index)}
                >
                  {hasSources && (
                    <span className="expand-icon">
                      {isExpanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                    </span>
                  )}
                  <div className="top-list-bar-container">
                    <div
                      className="top-list-bar blocked"
                      style={{ width: `${(count / maxCount) * 100}%` }}
                    />
                    <span className="top-list-name">{name}</span>
                  </div>
                  <span className="top-list-count">{count}</span>
                </div>

                {isExpanded && sources.length > 0 && (
                  <div className="expanded-sources">
                    <div className="sources-header">
                      <span>Source IP</span>
                      <span>Attempts</span>
                    </div>
                    {sources.map((source, srcIndex) => {
                      // Handle two formats:
                      // - Blocked sites: [srcip, count]
                      // - Blocked categories: [srcip, destination, count]
                      const hasDestination = source.length === 3;
                      const srcip = source[0];
                      const destination = hasDestination ? source[1] : name;
                      const srcCount = hasDestination ? source[2] : source[1];

                      return (
                        <div key={srcIndex} className="source-item">
                          <span className="source-ip">{srcip}</span>
                          <span className="source-arrow">→</span>
                          <span className="source-dest">{destination}</span>
                          <span className="source-count">{srcCount}</span>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};

export default ExpandableTopList;
