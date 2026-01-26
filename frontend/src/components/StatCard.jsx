const StatCard = ({ title, value, icon: Icon, color = 'text-white' }) => {
  return (
    <div className="stat-card">
      <div className="stat-header">
        {Icon && <Icon size={20} className="stat-icon" />}
        <span className="stat-title">{title}</span>
      </div>
      <div className={`stat-value ${color}`}>
        {typeof value === 'number' ? value.toLocaleString() : value}
      </div>
    </div>
  );
};

export default StatCard;
