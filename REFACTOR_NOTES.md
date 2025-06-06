# MantaGuard Refactoring Notes

## Overview
The original monolithic `MANTAGUARD.py` file (1290 lines) has been refactored into a modular structure for better maintainability and organization.

## New Structure

```
MantaGuard/
├── app.py                          # Main application entry point
├── MANTAGUARD_old.py            # Backup of original file
├── src/                            # Source code modules
│   ├── __init__.py
│   ├── utils/                      # Utility modules
│   │   ├── __init__.py
│   │   ├── config.py               # Configuration and setup functions
│   │   ├── session_state.py        # Session state management
│   │   └── navigation.py           # Sidebar navigation logic
│   └── pages/                      # Page modules
│       ├── __init__.py
│       ├── home_page.py            # Homepage content and styling
│       ├── scanning_page.py        # Network scanning functionality
│       ├── reports_page.py         # Reports and visualizations
│       └── fix_patches_page.py     # Fix & patches page
└── ... (other existing files)
```

## Module Breakdown

### `app.py` (Main Entry Point)
- Orchestrates all modules
- Handles page routing
- Manages application flow

### `src/utils/config.py`
- Page configuration setup
- Base64 file conversion utilities
- Directory creation functions

### `src/utils/session_state.py`
- Centralized session state initialization
- Thread-safe state updates processing
- Error message handling

### `src/utils/navigation.py`
- Sidebar navigation setup
- Navigation change handling
- Page switching logic

### `src/pages/home_page.py`
- Homepage rendering
- Hero banner and features section
- Tools showcase
- CSS styling

### `src/pages/scanning_page.py`
- Network scanning functionality
- Timed capture tab
- PCAP upload tab
- Results display tab
- AI model integration

### `src/pages/reports_page.py`
- Analysis results visualization
- PCAP extraction for forensics
- CSV data display
- Graph generation

### `src/pages/fix_patches_page.py`
- Fix and patches page (basic structure)

## Benefits of Refactoring

1. **Modularity**: Each component has a specific responsibility
2. **Maintainability**: Easier to locate and modify specific functionality
3. **Reusability**: Components can be reused across different parts of the application
4. **Testability**: Individual modules can be tested in isolation
5. **Readability**: Smaller, focused files are easier to understand
6. **Collaboration**: Multiple developers can work on different modules simultaneously

## Running the Application

To run the refactored application:

```bash
# Using the new modular structure
uv run streamlit run app.py

# Or using the original file (backup)
uv run streamlit run MANTAGUARD_old.py
```

## Migration Notes

- All functionality from the original file has been preserved
- No breaking changes to the user interface
- AI model imports and paths have been maintained
- Session state management remains compatible
- Threading and queue operations are preserved

## Future Improvements

1. Add unit tests for each module
2. Create configuration files for settings
3. Add logging functionality
4. Implement error handling improvements
5. Add API documentation
6. Create deployment configurations