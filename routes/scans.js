var express = require('express');
var controller = require('../controllers/scanController');
var router = express.Router();

router.post('/', controller.createScan);
router.get('/', controller.listScans);
router.get('/:id', controller.getScan);
router.patch('/:id/findings/:findingId', controller.updateFinding);
router.delete('/:id', controller.deleteScan);

module.exports = router;
