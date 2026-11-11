SELECT * FROM logs WHERE EventID=1 AND (EventID=1 AND (Image LIKE '%\\certutil.exe' ESCAPE '\' AND (CommandLine LIKE '%urlcache%' ESCAPE '\' OR CommandLine LIKE '%verifyctl%' ESCAPE '\')))
