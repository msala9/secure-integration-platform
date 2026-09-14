import { useEffect, useState } from 'react';

export function useDirectorySearch() {
  const [text, setText] = useState('');
  const [filter, setFilter] = useState('');
  useEffect(() => {
    const timer = setTimeout(() => setFilter(text.trim()), 250);
    return () => clearTimeout(timer);
  }, [text]);
  return { text, filter, setText };
}
