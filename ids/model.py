"""Design Section 7.3 temporal CNN. Returns uncalibrated binary logits."""

import torch
from torch import nn


class TemporalCNN(nn.Module):
    def __init__(self, channels=(64, 32)):
        super().__init__()
        if len(channels) != 2 or any(type(c) is not int or c <= 0 for c in channels):
            raise ValueError("Two positive integer channel counts are required")
        self.conv1 = nn.Conv1d(16, channels[0], 3, padding=1, bias=True)
        self.conv2 = nn.Conv1d(channels[0], channels[1], 3, padding=1, bias=True)
        self.output = nn.Linear(channels[1], 1, bias=True)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = torch.relu(self.conv1(x))
        x = torch.relu(self.conv2(x))
        return self.output(x.mean(dim=2))
