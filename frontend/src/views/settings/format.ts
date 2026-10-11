import { format } from 'date-fns';

// Display formatters shared by the settings areas (IP whitelist dates and the
// System Information card's counts and timestamps).

export const formatNumber = (num: number): string => {
  return new Intl.NumberFormat().format(num);
};

export const formatDate = (date: string): string => {
  return format(new Date(date), 'MMM dd, yyyy HH:mm');
};
