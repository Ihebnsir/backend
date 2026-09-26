var express = require('express');
var controller = require('../controllers/scanController');
var protect = require('../middleware/auth').protect;
var router = express.Router();

router.post('/', protect, controller.createScan);
router.get('/', protect, controller.listScans);
router.get('/:id', protect, controller.getScan);
router.patch('/:id/findings/:findingId', protect, controller.updateFinding);
router.delete('/:id', protect, controller.deleteScan);

module.exports = router;
