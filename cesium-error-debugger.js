/**
 * Cesium Error Debugger for RF SCYTHE
 * 
 * This module provides functions to debug and diagnose Cesium rendering errors
 */

// Create RF_SCYTHE namespace if it doesn't exist
window.RF_SCYTHE = window.RF_SCYTHE || {};

/**
 * Check for entities with invalid positions that might cause rendering errors
 * @param {Cesium.Viewer} viewer - The Cesium viewer to check
 * @returns {Array} Array of entities with invalid positions
 */
RF_SCYTHE.findEntitiesWithInvalidPositions = function(viewer) {
    if (!viewer || !viewer.entities) {
        console.warn('Invalid viewer provided');
        return [];
    }
    
    const invalidEntities = [];
    
    try {
        viewer.entities.values.forEach(entity => {
            try {
                if (!entity.position) {
                    // Skip entities without positions
                    return;
                }
                
                // Try to get current position
                const position = entity.position.getValue(Cesium.JulianDate.now());
                
                // Check if position is valid
                if (!position || 
                    !Cesium.defined(position) || 
                    !Cesium.defined(position.x) || 
                    !Cesium.defined(position.y) || 
                    !Cesium.defined(position.z) ||
                    !isFinite(position.x) || 
                    !isFinite(position.y) || 
                    !isFinite(position.z)) {
                    
                    invalidEntities.push({
                        entity: entity,
                        reason: 'Invalid or undefined position'
                    });
                    return;
                }
                
                // Try to convert to cartographic to check longitude/latitude
                try {
                    const cartographic = Cesium.Cartographic.fromCartesian(position);
                    if (!cartographic || 
                        !Cesium.defined(cartographic.longitude) || 
                        !Cesium.defined(cartographic.latitude)) {
                        
                        invalidEntities.push({
                            entity: entity,
                            reason: 'Invalid cartographic coordinates'
                        });
                    }
                } catch (error) {
                    invalidEntities.push({
                        entity: entity,
                        reason: 'Error converting to cartographic: ' + error.message
                    });
                }
            } catch (error) {
                invalidEntities.push({
                    entity: entity,
                    reason: 'Error checking position: ' + error.message
                });
            }
        });
    } catch (error) {
        console.error('Error finding entities with invalid positions:', error);
    }
    
    return invalidEntities;
};

/**
 * Check for geometry instances that might cause rendering errors
 * @param {Cesium.Viewer} viewer - The Cesium viewer to check
 */
RF_SCYTHE.debugCesiumGeometries = function(viewer) {
    if (!viewer || !viewer.scene) {
        console.warn('Invalid viewer provided');
        return;
    }
    
    const primitives = viewer.scene.primitives;
    let issues = 0;
    
    try {
        for (let i = 0; i < primitives.length; i++) {
            const primitive = primitives.get(i);
            
            // Skip non-ground primitives or undefined primitives
            if (!primitive || !primitive._groundPrimitives) {
                continue;
            }
            
            if (primitive._ellipseGeometries) {
                primitive._ellipseGeometries.forEach((geometry, index) => {
                    try {
                        if (!geometry.center || 
                            !Cesium.defined(geometry.center.x) || 
                            !isFinite(geometry.center.x)) {
                            
                            console.warn(`Invalid ellipse geometry at index ${index}`);
                            issues++;
                        }
                    } catch (error) {
                        console.warn(`Error checking ellipse geometry at index ${index}:`, error);
                        issues++;
                    }
                });
            }
        }
    } catch (error) {
        console.error('Error debugging Cesium geometries:', error);
    }
    
    return issues;
};

/**
 * Fix or remove entities with invalid positions to prevent rendering errors
 * @param {Cesium.Viewer} viewer - The Cesium viewer to fix
 * @returns {number} Number of entities fixed or removed
 */
RF_SCYTHE.fixEntitiesWithInvalidPositions = function(viewer) {
    if (!viewer || !viewer.entities) {
        console.warn('Invalid viewer provided');
        return 0;
    }
    
    const invalidEntities = RF_SCYTHE.findEntitiesWithInvalidPositions(viewer);
    let fixed = 0;
    
    invalidEntities.forEach(item => {
        try {
            // Try to fix the entity by setting a valid position
            if (item.entity.ellipse) {
                // For ellipses, we'll use a safe position
                const safePosition = Cesium.Cartesian3.fromDegrees(0, 0, 0);
                item.entity.position = safePosition;
                
                // Add a non-zero rotation to avoid bugs
                if (item.entity.ellipse.rotation) {
                    item.entity.ellipse.rotation = 0.001;
                }
                
                fixed++;
                
                // Add a console message about the fix
                if (typeof addConsoleMessage === 'function') {
                    addConsoleMessage(`Fixed entity with invalid position: ${item.entity.id || 'Unknown'}`, 'response');
                }
            } else {
                // For other entities, it's safer to remove them
                viewer.entities.remove(item.entity);
                fixed++;
                
                // Add a console message about the removal
                if (typeof addConsoleMessage === 'function') {
                    addConsoleMessage(`Removed entity with invalid position: ${item.entity.id || 'Unknown'}`, 'alert');
                }
            }
        } catch (error) {
            console.error('Error fixing entity:', error);
            
            // If fixing failed, remove the entity
            try {
                viewer.entities.remove(item.entity);
                fixed++;
            } catch (removeError) {
                console.error('Error removing entity:', removeError);
            }
        }
    });
    
    return fixed;
};

/**
 * Add a button to the UI to run the diagnostic and fix functions
 * @param {Cesium.Viewer} viewer - The Cesium viewer to debug
 */
RF_SCYTHE.addDebugButton = function(viewer) {
    // Create a debug button
    const button = document.createElement('button');
    button.textContent = 'Fix Rendering Errors';
    button.style.position = 'absolute';
    button.style.bottom = '10px';
    button.style.right = '10px';
    button.style.zIndex = '1000';
    button.style.padding = '5px 10px';
    button.style.backgroundColor = '#c93840';
    button.style.color = 'white';
    button.style.border = 'none';
    button.style.borderRadius = '3px';
    button.style.cursor = 'pointer';
    
    // Add event listener
    button.addEventListener('click', () => {
        // Find and fix invalid entities
        const fixed = RF_SCYTHE.fixEntitiesWithInvalidPositions(viewer);
        
        // Check for geometry issues
        const issues = RF_SCYTHE.debugCesiumGeometries(viewer);
        
        // Create a notification about the fixes
        if (typeof showNotification === 'function') {
            showNotification(
                'Rendering Error Fix',
                `Fixed ${fixed} entities with invalid positions. Found ${issues} geometry issues.`,
                'info'
            );
        }
        
        // Add console message
        if (typeof addConsoleMessage === 'function') {
            addConsoleMessage(`Fixed ${fixed} entities with invalid positions`, 'response');
        }
    });
    
    // Add to the DOM
    document.body.appendChild(button);
};

// Initialize debug button if we're in a browser environment with a console
if (typeof window !== 'undefined' && typeof console !== 'undefined') {
    // We'll wait for Cesium to be fully loaded
    window.addEventListener('load', function() {
        // Wait a bit for the viewer to be initialized
        setTimeout(function() {
            if (window.viewer) {
                RF_SCYTHE.addDebugButton(window.viewer);
            }
        }, 2000);
    });
}
