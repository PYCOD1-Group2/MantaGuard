import streamlit as st
import time

# Page config
st.set_page_config(
    page_title='MANTAGUARD',
    page_icon='https://raw.githubusercontent.com/aaron789746/MANTAGUARD/main/MANTAGUAD.png',)

# Sidebar navigation
st.sidebar.title("🔧 MantaGuard Features")
selected_option = st.sidebar.radio(
    "Navigate to:",
    ("Home", "Scanning", "Reports", "Vulnerabilities", "Fix & Patches")
)

# Page content based on selection
if selected_option == "Home":
    st.image("https://raw.githubusercontent.com/aaron789746/MANTAGUARD/main/MANTAGUAD.png", width=150)
    st.title("Welcome to MantaGuard 🛡️")
    st.subheader("Real-time Monitoring and Intrusion Detection using AI")
    st.write("Get started by selecting an option from the sidebar.")
    st.markdown("---")
    # Brief project description (you can customize this text)
    st.write("""
    **MantaGuard** is an AI-powered monitoring and intrusion detection system. 
    It utilizes advanced algorithms and real-time data processing to ensure environmental security and safety.
    """)

    # Tools Showcase
    st.subheader("🧰 Tools Used")

    cols = st.columns(4)

    with cols[0]:
        st.image("https://raw.githubusercontent.com/aaron789746/MANTAGUARD/main/streamlit.png", width=60)
        st.caption("Streamlit")

    with cols[1]:
        st.image("https://raw.githubusercontent.com/aaron789746/MANTAGUARD/main/Visual_Studio_Code_1.35_icon.svg.png", width=60)
        st.caption("VS Code")

    with cols[2]:
        st.image("https://raw.githubusercontent.com/aaron789746/MANTAGUARD/main/Python.svg.png", width=60)
        st.caption("Python")

    with cols[3]:
        st.image("https://raw.githubusercontent.com/aaron789746/MANTAGUARD/main/KNN.png", width=60)
        st.caption("KNN AI")

elif selected_option == "Scanning":
    st.title("📡 Live Scanning")

    # Initialize scan state
    if "scanning" not in st.session_state:
        st.session_state.scanning = False

    # Determine button label
    scan_label = "🚨 Start Scan" if not st.session_state.scanning else "🛑 Stop Scan"

    # Centered scan button
    left, center, right = st.columns([1, 2, 1])

    with center:
        if st.button(scan_label, key="scan_button"):
            st.session_state.scanning = not st.session_state.scanning
            st.rerun()

    # Scanning animation
    if st.session_state.scanning:
        scan_placeholder = st.empty()
        for i in range(50):
            if not st.session_state.scanning:
                break
            dots = "." * ((i % 3) + 1)
            scan_placeholder.markdown(f"### 🔍 Scanning{dots}")
            time.sleep(0.4)
        scan_placeholder.markdown("### ✅ Scan Complete")



elif selected_option == "Reports":
    st.title("📊 Reports")
    st.write("Here you can view generated reports and activity logs.")
    # Add more functionality here

elif selected_option == "Vulnerabilities":
    st.title("🛡️ Vulnerabilities")
    st.write("Detected vulnerabilities in the monitored environment.")
    # Add a table or list of vulnerabilities

elif selected_option == "Fix & Patches":
    st.title("🛠️ Fix & Patches")
    st.write("Suggested fixes and patches for identified vulnerabilities.")
    # Maybe upload patch files or show instructions
