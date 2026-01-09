import { Router } from 'express';
import {
    getProjects,
    getProject,
    createProject,
    deleteProject,
    startScan,
    getScanStatus,
    getScanLogs,
    getProjectEndpoints,
    getProjectScanHistory
} from '../controllers/projectController';

const router = Router();

router.get('/', getProjects);
router.get('/:id', getProject);
router.post('/', createProject);
router.delete('/:id', deleteProject);
router.get('/:id/endpoints', getProjectEndpoints);
router.get('/:id/history', getProjectScanHistory);
router.post('/:id/scan', startScan);
router.get('/scan/:scanId', getScanStatus);
router.get('/scan/:scanId/logs', getScanLogs);

export default router;
