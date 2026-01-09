import { Router } from 'express';
import {
    getAttackGraph,
    getNodeDetails,
    updateAttackGraph,
    analyzeAttackGraph
} from '../controllers/attackGraphController';

const router = Router();

// GET /api/attack-graph/:scanId - Get attack graph for a scan
router.get('/:scanId', getAttackGraph);

// GET /api/attack-graph/node/:nodeId - Get details for a specific node
router.get('/node/:nodeId', getNodeDetails);

// PUT /api/attack-graph/:scanId - Update attack graph for a scan
router.put('/:scanId', updateAttackGraph);

// POST /api/attack-graph/:scanId/analyze - Analyze attack graph
router.post('/:scanId/analyze', analyzeAttackGraph);

export default router;
