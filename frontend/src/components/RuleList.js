import React from 'react';
import {
  Accordion,
  AccordionSummary,
  AccordionDetails,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
  Switch,
  Typography,
  Box,
  CircularProgress,
  Chip,
  Divider,
  TextField,
  InputAdornment
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import SearchIcon from '@mui/icons-material/Search';
import { memo, useState } from 'react';

const RuleComponent = memo(({ rule, handleToggleRule, category }) => (
  <React.Fragment>
    <ListItem disableGutters>
      <ListItemText 
        primary={
          <Box sx={{ display: 'flex', alignItems: 'center' }}>
            <Typography variant="body2">{rule.title}</Typography>
            <Chip
              label={rule.severity}
              color={getSeverityColor(rule.severity)}
              size="small"
              sx={{ ml: 1 }}
            />
          </Box>
        }
        secondary={rule.description}
      />
      <ListItemSecondaryAction>
        <Switch
          size="small"
          checked={rule.enabled}
          onChange={() => handleToggleRule(rule.id, rule.enabled, category)}
        />
      </ListItemSecondaryAction>
    </ListItem>
    <Divider />
  </React.Fragment>
));

const getSeverityColor = (severity) => {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 'error';
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
      return 'info';
    default:
      return 'default';
  }
};

const SubcategoryAccordion = ({ subcategory, rules, handleToggleRule, searchTerm }) => {
  const filteredRules = rules.filter(rule => 
    rule.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
    (rule.description && rule.description.toLowerCase().includes(searchTerm.toLowerCase()))
  );

  if (filteredRules.length === 0) return null;

  const enabledCount = filteredRules.filter(r => r.enabled).length;
  const totalCount = filteredRules.length;

  const severityCounts = filteredRules.reduce((acc, rule) => {
    const severity = rule.severity.toLowerCase();
    acc[severity] = (acc[severity] || 0) + 1;
    return acc;
  }, {});

  return (
    <Accordion>
      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
        <Box sx={{ display: 'flex', alignItems: 'center', width: '100%' }}>
          <Typography variant="body1" sx={{ flexGrow: 1 }}>
            {subcategory}
          </Typography>
          <Box sx={{ display: 'flex', gap: 1 }}>
            {Object.entries(severityCounts).map(([severity, count]) => (
              <Chip
                key={severity}
                label={`${severity}: ${count}`}
                color={getSeverityColor(severity)}
                size="small"
              />
            ))}
            <Chip 
              label={`${enabledCount}/${totalCount} enabled`}
              color={enabledCount > 0 ? 'primary' : 'default'}
              size="small"
            />
          </Box>
        </Box>
      </AccordionSummary>
      <AccordionDetails>
        <List>
          {filteredRules.map((rule) => (
            <RuleComponent
              key={rule.id}
              rule={rule}
              handleToggleRule={handleToggleRule}
              category={rule.category}
            />
          ))}
        </List>
      </AccordionDetails>
    </Accordion>
  );
};

const CategoryAccordion = ({ category, rules, handleToggleRule, searchTerm }) => {
  // Group rules by subcategory
  const subcategories = rules.reduce((acc, rule) => {
    const [, ...subcategoryParts] = rule.category.split('/');
    const subcategory = subcategoryParts.join('/') || 'general';
    if (!acc[subcategory]) {
      acc[subcategory] = [];
    }
    acc[subcategory].push(rule);
    return acc;
  }, {});

  const totalRules = rules.length;
  const enabledRules = rules.filter(r => r.enabled).length;
  const subcategoryCount = Object.keys(subcategories).length;

  return (
    <Accordion>
      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
        <Box sx={{ display: 'flex', alignItems: 'center', width: '100%' }}>
          <Typography variant="h6" sx={{ flexGrow: 1 }}>
            {category.charAt(0).toUpperCase() + category.slice(1)}
          </Typography>
          <Box sx={{ display: 'flex', gap: 1 }}>
            <Chip
              label={`${subcategoryCount} subcategories`}
              size="small"
              variant="outlined"
            />
            <Chip 
              label={`${enabledRules}/${totalRules} enabled`}
              color={enabledRules > 0 ? 'primary' : 'default'}
              size="small"
            />
          </Box>
        </Box>
      </AccordionSummary>
      <AccordionDetails>
        <Box sx={{ pl: 2 }}>
          {Object.entries(subcategories)
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([subcategory, subcategoryRules]) => (
              <SubcategoryAccordion
                key={subcategory}
                subcategory={subcategory}
                rules={subcategoryRules}
                handleToggleRule={handleToggleRule}
                searchTerm={searchTerm}
              />
            ))}
        </Box>
      </AccordionDetails>
    </Accordion>
  );
};

const RuleList = ({ rules, loading, handleToggleRule }) => {
  const [searchTerm, setSearchTerm] = useState('');

  // Group rules by top-level category
  const groupedRules = rules.reduce((acc, rule) => {
    const topCategory = rule.category.split('/')[0] || 'uncategorized';
    if (!acc[topCategory]) {
      acc[topCategory] = [];
    }
    acc[topCategory].push(rule);
    return acc;
  }, {});

  return (
    <>
      <Box sx={{ mb: 2 }}>
        <TextField
          fullWidth
          variant="outlined"
          size="small"
          placeholder="Search rules..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <SearchIcon />
              </InputAdornment>
            ),
          }}
        />
      </Box>

      {loading ? (
        <Box sx={{ display: 'flex', justifyContent: 'center', p: 3, mt: 2 }}>
          <CircularProgress />
        </Box>
      ) : (
        Object.entries(groupedRules)
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([category, categoryRules]) => (
            <CategoryAccordion
              key={category}
              category={category}
              rules={categoryRules}
              handleToggleRule={handleToggleRule}
              searchTerm={searchTerm}
            />
          ))
      )}
    </>
  );
};

export default RuleList;