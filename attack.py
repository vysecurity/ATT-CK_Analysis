from stix2 import FileSystemSource
from stix2 import Filter
from stix2.utils import get_type_from_id

fs = FileSystemSource('./enterprise-attack')

def get_group_by_alias(src):
    return src.query([
        Filter('type', '=', 'intrusion-set'),
    ])
	
def get_techniques_by_group_software(src, group_stix_id):
    # get the malware, tools that the group uses
    group_uses = [
        r for r in src.relationships(group_stix_id, 'uses', source_only=True)
        if get_type_from_id(r.target_ref) in ['malware', 'tool']
    ]

    # get the technique stix ids that the malware, tools use
    software_uses = src.query([
        Filter('type', '=', 'relationship'),
        Filter('relationship_type', '=', 'uses'),
        Filter('source_ref', 'in', [r.source_ref for r in group_uses])
    ])

    #get the techniques themselves
    return src.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('id', 'in', [r.target_ref for r in software_uses])
    ])
    

groups = get_group_by_alias(fs)

for group in groups:
	techniques = get_techniques_by_group_software(fs, group)
	for technique in techniques:
		print group['name'] + "," + technique['name']

