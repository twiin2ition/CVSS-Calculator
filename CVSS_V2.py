import tkinter as tk

# Define the weights for each metric globally
av_weights = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}
ac_weights = {'H': 0.44, 'L': 0.77}
pr_weights = {'N': 0.85, 'L': 0.62, 'H': 0.27}
ui_weights = {'N': 0.85, 'R': 0.62}
s_weights = {'U': 6.42, 'C': 7.52}
c_weights = {'N': 0, 'L': 0.22, 'H': 0.56}
i_weights = {'N': 0, 'L': 0.22, 'H': 0.56}
a_weights = {'N': 0, 'L': 0.22, 'H': 0.56}

def calculate_cvss_score():
    av_value = av_var.get()
    ac_value = ac_var.get()
    pr_value = pr_var.get()
    ui_value = ui_var.get()
    s_value = s_var.get()
    c_value = c_var.get()
    i_value = i_var.get()
    a_value = a_var.get()

    # Calculate Impact Sub-Score and round to the nearest hundredth
    impact_sub_score = round((1 - ((1 - c_weights[c_value]) * (1 - i_weights[i_value]) * (1 - a_weights[a_value]))), 2)

    # Calculate Impact Score and round to the nearest hundredth
    if s_value == "U":
        impact_score = round(6.42 * impact_sub_score, 2)
    else:  # scope is changed
        impact_score = round(7.52 * (impact_sub_score - 0.029) - 3.25 * ((impact_sub_score - 0.02) ** 15), 2)

    # Calculate Exploitability Score and round to the nearest hundredth
    exploitability_score = round(8.22 * av_weights[av_value] * ac_weights[ac_value] * pr_weights[pr_value] * ui_weights[ui_value], 2)

    # Calculate the base score
    base_score = round(impact_score + exploitability_score, 1)

    # Determine the CVSS rating based on the calculated score (CVSS version 3.0)
    if base_score == 0.0:
        rating = "None"
    elif 0.1 <= base_score <= 3.9:
        rating = "Low"
    elif 4.0 <= base_score <= 6.9:
        rating = "Medium"
    elif 7.0 <= base_score <= 8.9:
        rating = "High"
    else:
        rating = "Critical"
        base_score = 10.0  # Cap the score at 10.0

    # Update the labels with the calculated scores and rating
    impact_sub_score_label.config(text=f"Impact Sub-Score: {impact_sub_score}")
    impact_score_label.config(text=f"Impact Score: {impact_score}")
    exploitability_score_label.config(text=f"Exploitability Score: {exploitability_score}")
    severity_value_label.config(text=f"{base_score} ({rating})")

def reset_values():
    # Reset all the radio button values to NULL
    av_var.set(None)
    ac_var.set(None)
    pr_var.set(None)
    ui_var.set(None)
    s_var.set(None)
    c_var.set(None)
    i_var.set(None)
    a_var.set(None)
    
    # Clear the calculated scores and rating labels
    impact_sub_score_label.config(text="Impact Sub-Score: -")
    impact_score_label.config(text="Impact Score: -")
    exploitability_score_label.config(text="Exploitability Score: -")
    severity_value_label.config(text="Qualitative Severity Score: -")

# Create the main window
root = tk.Tk()
root.title("CVSS Calculator")

# Create labels and radio buttons for each CVSS metric
av_label = tk.Label(root, text="Attack Vector:")
av_label.grid(row=1, column=0, sticky="w")
av_var = tk.StringVar(value="N")
av_options = [("Network", "N"), ("Adjacent Network", "A"), ("Local", "L"), ("Physical", "P")]
for i, (text, value) in enumerate(av_options):
    av_rb = tk.Radiobutton(root, text=text, variable=av_var, value=value)
    av_rb.grid(row=1, column=i+1)

ac_label = tk.Label(root, text="Attack Complexity:")
ac_label.grid(row=2, column=0, sticky="w")
ac_var = tk.StringVar(value="L")
ac_options = [("Low", "L"), ("High", "H")]
for i, (text, value) in enumerate(ac_options):
    ac_rb = tk.Radiobutton(root, text=text, variable=ac_var, value=value)
    ac_rb.grid(row=2, column=i+1)

pr_label = tk.Label(root, text="Privileges Required:")
pr_label.grid(row=3, column=0, sticky="w")
pr_var = tk.StringVar(value="N")
pr_options = [("None", "N"), ("Low", "L"), ("High", "H")]
for i, (text, value) in enumerate(pr_options):
    pr_rb = tk.Radiobutton(root, text=text, variable=pr_var, value=value)
    pr_rb.grid(row=3, column=i+1)

ui_label = tk.Label(root, text="User Interaction:")
ui_label.grid(row=4, column=0, sticky="w")
ui_var = tk.StringVar(value="N")
ui_options = [("None", "N"), ("Required", "R")]
for i, (text, value) in enumerate(ui_options):
    ui_rb = tk.Radiobutton(root, text=text, variable=ui_var, value=value)
    ui_rb.grid(row=4, column=i+1)

s_label = tk.Label(root, text="Scope:")
s_label.grid(row=5, column=0, sticky="w")
s_var = tk.StringVar(value="U")
s_options = [("Unchanged", "U"), ("Changed", "C")]
for i, (text, value) in enumerate(s_options):
    s_rb = tk.Radiobutton(root, text=text, variable=s_var, value=value)
    s_rb.grid(row=5, column=i+1)

c_label = tk.Label(root, text="Confidentiality:")
c_label.grid(row=6, column=0, sticky="w")
c_var = tk.StringVar(value="H")
c_options = [("None", "N"), ("Low", "L"), ("High", "H")]
for i, (text, value) in enumerate(c_options):
    c_rb = tk.Radiobutton(root, text=text, variable=c_var, value=value)
    c_rb.grid(row=6, column=i+1)

i_label = tk.Label(root, text="Integrity:")
i_label.grid(row=7, column=0, sticky="w")
i_var = tk.StringVar(value="H")
i_options = [("None", "N"), ("Low", "L"), ("High", "H")]
for i, (text, value) in enumerate(i_options):
    i_rb = tk.Radiobutton(root, text=text, variable=i_var, value=value)
    i_rb.grid(row=7, column=i+1)

a_label = tk.Label(root, text="Availability:")
a_label.grid(row=8, column=0, sticky="w")
a_var = tk.StringVar(value="H")
a_options = [("None", "N"), ("Low", "L"), ("High", "H")]
for i, (text, value) in enumerate(a_options):
    a_rb = tk.Radiobutton(root, text=text, variable=a_var, value=value)
    a_rb.grid(row=8, column=i+1)

# Add labels to display the calculated scores
impact_sub_score_label = tk.Label(root, text="Impact Sub-Score: -")
impact_sub_score_label.grid(row=9, columnspan=3)

impact_score_label = tk.Label(root, text="Impact Score: -")
impact_score_label.grid(row=10, columnspan=3)

exploitability_score_label = tk.Label(root, text="Exploitability Score: -")
exploitability_score_label.grid(row=11, columnspan=3)

severity_value_label = tk.Label(root, text="Qualitative Severity Score: -")
severity_value_label.grid(row=12, columnspan=3)

# Add a button to calculate the CVSS score
calculate_button = tk.Button(root, text="Calculate", command=calculate_cvss_score)
calculate_button.grid(row=14, column=1, pady=10)

# Add a button to reset the values
reset_button = tk.Button(root, text="Reset", command=reset_values)
reset_button.grid(row=14, column=2, pady=10)

# Store all radio buttons in a list
all_radiobuttons = []

# Set initial values for radio buttons to None
av_var.set(None)
ac_var.set(None)
pr_var.set(None)
ui_var.set(None)
s_var.set(None)
c_var.set(None)
i_var.set(None)
a_var.set(None)

# Start the GUI event loop
root.mainloop()

