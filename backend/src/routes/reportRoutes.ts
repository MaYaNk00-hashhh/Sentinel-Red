import { Router } from 'express';
import { getReport, exportReportPDF } from '../controllers/reportController';

const router = Router();

router.get('/:scanId', getReport);
router.get('/:scanId/pdf', exportReportPDF);

export default router;