from pathlib import Path
root=Path(__file__).resolve().parents[1]
base='''index=week5_hunt sourcetype=week5_json earliest=0 latest=now
| spath
| rename "host.id" AS host_id "event.category" AS category "process.entity_id" AS entity_id "process.name" AS process_name "process.parent.name" AS parent_name "process.command_line" AS command_line "network.direction" AS direction
| eval host_id=mvindex(host_id,0), category=mvindex(category,0), entity_id=mvindex(entity_id,0), process_name=mvindex(process_name,0), parent_name=mvindex(parent_name,0), command_line=mvindex(command_line,0), direction=mvindex(direction,0), event_time=strptime(mvindex('@timestamp',0), "%Y-%m-%dT%H:%M:%SZ")
| eval is_ps=if(in(lower(process_name), "powershell.exe", "pwsh.exe"),1,0), is_office=if(in(lower(parent_name), "winword.exe", "excel.exe"),1,0), is_encoded=if(match(lower(command_line), " -enc(odedcommand)? "),1,0)'''
queries={
'q1_powershell':base+'\n| where category="process" AND is_ps=1\n| table host_id entity_id parent_name command_line',
'q2_office_parent':base+'\n| where category="process" AND is_ps=1 AND is_office=1\n| table host_id entity_id parent_name command_line',
'q3_encoded_office':base+'\n| where category="process" AND is_ps=1 AND is_office=1 AND is_encoded=1\n| table host_id entity_id parent_name command_line',
'q4_correlated_sequence':base+'''\n| eval candidate_time=if(category="process" AND is_ps=1 AND is_office=1 AND is_encoded=1,event_time,null()), outbound_time=if(category="network" AND direction="egress",event_time,null())
| stats min(candidate_time) AS process_time min(outbound_time) AS network_time by host_id entity_id
| where isnotnull(process_time) AND isnotnull(network_time) AND network_time>=process_time AND network_time-process_time<=600
| eval delay_seconds=network_time-process_time
| table host_id entity_id delay_seconds'''}
for name,q in queries.items():(root/'queries'/f'{name}.spl').write_text(q+'\n')
print('Prepared four Splunk SPL searches.')
