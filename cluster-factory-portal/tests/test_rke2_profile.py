import os
import unittest

os.environ.setdefault("WORKER_IMAGE", "example.test/factory:test")

from app import kube


class RancherProfileTests(unittest.TestCase):
    def test_accepts_supported_shapes(self):
        for control_planes in (1, 3, 5):
            for workers in (3, 4, 5, 6):
                self.assertIsNone(kube.rke2_request_error(control_planes, workers))

    def test_rejects_too_few_workers_and_other_control_plane_counts(self):
        for shape in ((1, 1), (1, 2), (2, 3), (4, 6), (5, 2)):
            self.assertIsNotNone(kube.rke2_request_error(*shape), shape)


if __name__ == "__main__":
    unittest.main()
