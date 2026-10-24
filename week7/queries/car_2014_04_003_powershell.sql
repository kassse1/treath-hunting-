SELECT * FROM logs WHERE EventID=1 AND (Image LIKE '%\\powershell.exe' ESCAPE '\' AND (NOT COALESCE((ParentImage LIKE '%\\explorer.exe' ESCAPE '\'), 0)))
