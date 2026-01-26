const TopList = ({ title, items, maxItems = 5 }) => {
  const displayItems = items.slice(0, maxItems);
  const maxCount = displayItems.length > 0 ? displayItems[0][1] : 0;

  return (
    <div className="top-list">
      <h3>{title}</h3>
      <div className="top-list-items">
        {displayItems.length === 0 ? (
          <div className="no-data">No data yet</div>
        ) : (
          displayItems.map(([name, count], index) => (
            <div key={index} className="top-list-item">
              <div className="top-list-bar-container">
                <div 
                  className="top-list-bar" 
                  style={{ width: `${(count / maxCount) * 100}%` }}
                />
                <span className="top-list-name">{name}</span>
              </div>
              <span className="top-list-count">{count}</span>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default TopList;
