import streamlit as st
from src.utils.config import get_base64_of_bin_file

def navigate_to_scanning():
    """Handle Get Started button click."""
    st.session_state.current_selection = "Scanning"
    st.session_state.previous_selection = "Home"
    st.rerun()

def render_css_styles(hero_banner_base64):
    """Render custom CSS styles for the homepage."""
    st.markdown("""
    <style>
    /* Reset some default Streamlit styles */
    .block-container {
        max-width: 90% !important;
        padding-top: 0 !important;
        padding-left: 0 !important;
        padding-right: 0 !important;
    }

    /* Banner section */
    .hero-banner {
        width: 100%;
        min-height: 500px;
        background: linear-gradient(rgba(0, 0, 0, 0.4), rgba(0, 0, 0, 0.4)), 
                    url(data:image/png;base64,""" + f"{hero_banner_base64}" + """);
        background-size: cover;
        background-position: center;
        background-repeat: no-repeat;
        display: flex;
        flex-direction: column;
        justify-content: center;
        align-items: center;
        padding: 40px 20px;
        text-align: center;
        margin-bottom: 20px;
        border-radius: 15px;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        position: relative;
    }

    /* Logo styling */
    .hero-logo {
        max-width: 200px;
        margin-bottom: 30px;
    }

    /* Headline styling */
    .hero-title {
        font-size: 3rem !important;
        font-weight: 700 !important;
        color: white !important;
        margin-bottom: 20px !important;
        line-height: 1.2 !important;
    }

    /* Subheadline styling */
    .hero-subtitle {
        font-size: 1.5rem !important;
        color: rgba(255, 255, 255, 0.8) !important;
        margin-bottom: 40px !important;
        max-width: 720px;
    }

    /* CTA button styling - enhanced for hero banner */
    .hero-cta {
        background-color: #00BFFF;
        color: white;
        font-weight: 600;
        padding: 12px 30px;
        border-radius: 30px;
        border: none;
        font-size: 1.1rem;
        cursor: pointer;
        transition: all 0.3s ease;
        text-decoration: none;
        display: inline-block;
        margin-top: 20px;
    }

    .hero-cta:hover {
        background-color: #00A0E0;
        box-shadow: 0 0 15px rgba(0, 191, 255, 0.5);
        transform: translateY(-2px);
    }
    
    /* Style Streamlit buttons within hero banner */
    .hero-banner .stButton > button {
        background-color: #00BFFF !important;
        color: white !important;
        border: none !important;
        border-radius: 30px !important;
        padding: 12px 30px !important;
        font-weight: 600 !important;
        font-size: 1.1rem !important;
        margin-top: 20px !important;
        transition: all 0.3s ease !important;
    }
    
    .hero-banner .stButton > button:hover {
        background-color: #00A0E0 !important;
        box-shadow: 0 0 15px rgba(0, 191, 255, 0.5) !important;
        transform: translateY(-2px) !important;
    }

    /* Features section styling */
    .features-section {
        padding: 80px 20px;
        max-width: 1080px;
        margin: 0 auto;
    }

    .features-title {
        font-size: 2.5rem !important;
        font-weight: 700 !important;
        text-align: center;
        margin-bottom: 10px !important;
    }

    .features-subtitle {
        font-size: 1.25rem !important;
        text-align: center;
        color: rgba(255, 255, 255, 0.8) !important;
        margin-bottom: 50px !important;
    }

    /* Feature card styling */
    .feature-card {
        background-color: #1E1E1E;
        border-radius: 8px;
        padding: 30px 20px;
        text-align: center;
        height: 100%;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        transition: all 0.3s ease;
    }

    .feature-card:hover {
        transform: translateY(-4px);
        box-shadow: 0 8px 16px rgba(0, 0, 0, 0.2);
    }

    .feature-icon {
        font-size: 2.5rem;
        margin-bottom: 20px;
        color: #00BFFF;
    }

    .feature-title {
        font-size: 1.5rem !important;
        font-weight: 700 !important;
        margin-bottom: 15px !important;
    }

    .feature-description {
        font-size: 1rem;
        color: rgba(255, 255, 255, 0.8);
    }

    /* Divider styling */
    .section-divider {
        border-top: 1px solid rgba(255, 255, 255, 0.1);
        margin: 40px 0;
    }

    /* Tool descriptions (existing styles) */
    .tool-title {
        font-size: 1.5rem;
        font-weight: bold;
        margin-bottom: 10px;
        text-align: center;
    }
    .tool-description {
        border-radius: 5px;
        padding: 20px;
        height: 100%;
        display: flex;
        align-items: center;
        font-size: 1rem;
        line-height: 1.6;
    }
    /* CSS for bottom alignment */
    .stVerticalBlock {
        display: flex;
        flex-direction: column;
    }
    .stImage {
        margin-top: auto;
        margin-bottom: 0;
        display: flex;
        align-items: flex-end;
    }
    /* CSS for tool images vertical centering */
    .tool-image {
        display: flex;
        align-items: center;
        justify-content: center;
        height: 100%;
        padding: 20px;
    }
    .tool-image img {
        max-width: 100%;
        height: auto;
        object-fit: contain;
    }

    /* Responsive styles */
    @media (max-width: 768px) {
        .hero-title {
            font-size: 2.5rem !important;
        }
        .hero-subtitle {
            font-size: 1.2rem !important;
        }
        .features-title {
            font-size: 2rem !important;
        }
    }
    </style>
    """, unsafe_allow_html=True)

def render_hero_banner():
    """Render the hero banner section."""
    st.markdown("""
    <div class="hero-banner">
        <div style="display: flex; flex-direction: column; align-items: center; z-index: 10; position: relative;">
            <img src="data:image/png;base64,""" + get_base64_of_bin_file('content/Group3.png') + """" 
                 class="hero-logo" alt="MantaGuard Logo" style="max-width: 200px; margin-bottom: 20px;">
            <h1 class="hero-title">Welcome to MantaGuard</h1>
            <h2 class="hero-subtitle">Real-time Monitoring and Intrusion Detection using AI</h2>
    """, unsafe_allow_html=True)
    
    # Add the "Get Started" button within the hero banner
    col1, col2, col3 = st.columns([2, 1, 2])
    with col2:
        st.button("Get Started", on_click=navigate_to_scanning, key="get_started_button", type="primary", use_container_width=True)
    
    # Close the hero banner div
    st.markdown("""
        </div>
    </div>
    """, unsafe_allow_html=True)

def render_features_section():
    """Render the features section."""
    features = [
        {
            "icon": "🧠",
            "title": "AI-Driven Anomaly Detection",
            "description": "Catches suspicious patterns in real time—24/7 monitoring."
        },
        {
            "icon": "🔔",
            "title": "Customizable Alerting",
            "description": "Get notified instantly when potential threats are detected."
        },
        {
            "icon": "📊",
            "title": "Easy Dashboard & Reporting",
            "description": "Visualize network activity and security insights at a glance."
        },
        {
            "icon": "🔒",
            "title": "Scalable & Secure",
            "description": "Enterprise-grade protection that grows with your network needs."
        }
    ]

    # Create the features section header
    st.markdown("""
    <div id="features" class="features-section">
        <h2 class="features-title">Why MantaGuard?</h2>
        <p class="features-subtitle">Our key features at a glance</p>
    """, unsafe_allow_html=True)

    # Create a 2x2 grid for features
    col1, col2 = st.columns(2)

    # First row
    with col1:
        st.markdown(f"""
        <div class="feature-card">
            <div class="feature-icon">{features[0]['icon']}</div>
            <h3 class="feature-title">{features[0]['title']}</h3>
            <p class="feature-description">{features[0]['description']}</p>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
        <div class="feature-card">
            <div class="feature-icon">{features[1]['icon']}</div>
            <h3 class="feature-title">{features[1]['title']}</h3>
            <p class="feature-description">{features[1]['description']}</p>
        </div>
        """, unsafe_allow_html=True)

    # Second row
    col3, col4 = st.columns(2)

    with col3:
        st.markdown(f"""
        <div class="feature-card">
            <div class="feature-icon">{features[2]['icon']}</div>
            <h3 class="feature-title">{features[2]['title']}</h3>
            <p class="feature-description">{features[2]['description']}</p>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        st.markdown(f"""
        <div class="feature-card">
            <div class="feature-icon">{features[3]['icon']}</div>
            <h3 class="feature-title">{features[3]['title']}</h3>
            <p class="feature-description">{features[3]['description']}</p>
        </div>
        """, unsafe_allow_html=True)

    # Close the features section
    st.markdown("""
    </div>
    <div class="section-divider"></div>
    """, unsafe_allow_html=True)

def render_tools_showcase():
    """Render the tools showcase section."""
    st.subheader("🧰 Tools Used")

    # Tool configurations
    tools = [
        {
            "name": "Streamlit",
            "image": "content/streamlit.png",
            "width": 150,
            "description": "Streamlit is an open-source Python library that makes it easy to create and share beautiful, custom web apps for machine learning and data science. In MantaGuard, Streamlit powers the entire user interface, providing interactive components like buttons, sliders, and visualizations that make network monitoring and intrusion detection accessible and user-friendly. Its ability to update in real-time makes it perfect for displaying live network data and analysis results."
        },
        {
            "name": "VS Code",
            "image": "content/Visual_Studio_Code_1.35_icon.svg.png",
            "width": 100,
            "description": "Visual Studio Code is a lightweight but powerful source code editor which runs on your desktop and is available for Windows, macOS and Linux. For MantaGuard development, VS Code provides essential features like integrated Git version control, debugging capabilities, and Python extensions that enhance productivity. Its customizable interface and extensive marketplace of extensions make it ideal for developing complex security applications that integrate multiple technologies and libraries."
        },
        {
            "name": "Python",
            "image": "content/Python.svg.png",
            "width": 100,
            "description": "Python is a programming language that lets you work quickly and integrate systems more effectively. It is used extensively in data science, machine learning, and AI applications. In MantaGuard, Python serves as the core programming language, enabling rapid development and integration of various security components. Its rich ecosystem of libraries like pandas for data manipulation, scikit-learn for machine learning, and network analysis tools makes it perfect for implementing sophisticated intrusion detection algorithms and processing network traffic data efficiently."
        },
        {
            "name": "OCSVM Algorithm",
            "image": "content/87ac3b54-afcc-40fe-84c2-515cc1415f3d.png",
            "width": 200,
            "description": "One-Class Support Vector Machine (OCSVM) is an unsupervised learning algorithm that learns a decision boundary that achieves the maximum separation between the points and the origin. In MantaGuard, OCSVM serves as the primary anomaly detection engine, capable of identifying unusual network patterns without requiring labeled training data. This makes it ideal for detecting zero-day attacks and previously unknown threats. The algorithm works by learning the normal behavior of network traffic and flagging deviations from this pattern, allowing MantaGuard to detect sophisticated intrusion attempts that might bypass traditional signature-based detection systems."
        },
        {
            "name": "Zeek Network Monitor",
            "image": "content/Zeek-Featured.png",
            "width": 200,
            "description": "Zeek (formerly Bro) is a powerful network analysis framework that is much different from the typical IDS you may know. It provides a comprehensive platform for network traffic analysis. In MantaGuard, Zeek serves as the primary data collection engine, capturing and parsing network traffic into structured logs that can be analyzed by the OCSVM algorithm. Its ability to extract detailed protocol-specific information from network flows enables MantaGuard to perform deep packet inspection and identify subtle patterns that might indicate malicious activity. Zeek's flexible scripting language also allows for customized detection rules tailored to specific network environments and threat landscapes."
        }
    ]

    for tool in tools:
        st.markdown(f'<div class="tool-title">{tool["name"]}</div>', unsafe_allow_html=True)
        
        tool_container = st.container()
        with tool_container:
            tool_row = st.columns([1, 2])
            
            with tool_row[0]:
                st.markdown('<div class="tool-image">', unsafe_allow_html=True)
                st.image(tool["image"], width=tool["width"])
                st.markdown('</div>', unsafe_allow_html=True)
            
            with tool_row[1]:
                st.markdown(f'<div class="tool-description">{tool["description"]}</div>', unsafe_allow_html=True)
        
        st.markdown("---")

def render_home_page():
    """Render the complete home page."""
    # Get the hero banner image as base64
    hero_banner_base64 = get_base64_of_bin_file('content/hero-banner.png')
    
    # Render CSS styles
    render_css_styles(hero_banner_base64)
    
    # Render hero banner
    render_hero_banner()
    
    # Render features section
    render_features_section()
    
    # Brief project description
    st.write("""
    **MantaGuard** is an AI-powered monitoring and intrusion detection system. 
    It utilizes advanced algorithms and real-time data processing to ensure environmental security and safety.
    """)
    
    # Render tools showcase
    render_tools_showcase()