import json
import copy

def categorize_intensity(desc):
    desc = desc.lower()
    if 'low' in desc: return 'low'
    if 'high' in desc: return 'high'
    if 'extreme' in desc: return 'high'
    return 'medium'

def generate_matrix_config():
    with open('attack/attack_config.json', 'r') as f:
        config = json.load(f)

    for attack_name, attack_data in config['attacks'].items():
        original_variations = attack_data.get('variations', [])
        
        # 1. Identify "Base" prototypes for Low and High intensity
        # We look for ANY existing variation that fits the profile to use as a template
        low_proto = next((v for v in original_variations if categorize_intensity(v.get('description', '')) == 'low'), None)
        high_proto = next((v for v in original_variations if categorize_intensity(v.get('description', '')) == 'high'), None)
        
        # Fallback if no explicit "high" (use medium)
        if not high_proto:
            high_proto = next((v for v in original_variations if categorize_intensity(v.get('description', '')) == 'medium'), None)

        new_variations = []
        
        # 2. Generate the Matrix
        
        # A) Flash Floods (High Intensity, 2s)
        if high_proto:
            v = copy.deepcopy(high_proto)
            v['duration'] = 2
            v['description'] = v['description'].split('-')[0].strip() + " - High Intensity Flash Burst (2s)"
            new_variations.append(v)

        # B) Standard Short (Low Intensity, 5s) - keep existing or create
        if low_proto:
            v = copy.deepcopy(low_proto)
            v['duration'] = 5
            v['description'] = v['description'].split('-')[0].strip() + " - Low Intensity Probe (5s)"
            new_variations.append(v)
            
        # C) Sustained Medium (Medium Intensity, 30s)
        # Try to find a medium proto, or mod the low/high
        med_proto = next((v for v in original_variations if categorize_intensity(v.get('description', '')) == 'medium'), low_proto)
        if med_proto:
            v = copy.deepcopy(med_proto)
            v['duration'] = 30
            v['description'] = v['description'].split('-')[0].strip() + " - Medium Sustained (30s)"
            new_variations.append(v)

        # D) Stealth / Low-and-Slow (Low Intensity, 180s)
        if low_proto:
            v = copy.deepcopy(low_proto)
            v['duration'] = 180
            v['delay'] = v.get('delay', 0.1) * 2 # Make it even slower for 180s stealth
            v['description'] = v['description'].split('-')[0].strip() + " - Low & Slow Stealth (180s)"
            new_variations.append(v)
            
        # E) Stress Test (High Intensity, 180s) - The one user questioned, but needed for 180s window training
        if high_proto:
            v = copy.deepcopy(high_proto)
            v['duration'] = 180
            v['description'] = v['description'].split('-')[0].strip() + " - High Intensity Flooding (180s)"
            new_variations.append(v)

        # Replace variations with this cleaner matrix
        attack_data['variations'] = new_variations
        print(f"Refined {attack_name}: {len(new_variations)} variations")

    with open('attack/attack_config.json', 'w') as f:
        json.dump(config, f, indent=4)
    
    print("Config matrix regeneration complete.")

if __name__ == "__main__":
    generate_matrix_config()
