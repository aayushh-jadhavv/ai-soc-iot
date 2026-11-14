"""Design Section 7.3. Returns logits, never trained attack predictions."""

import torch
from torch import nn


class TemporalCNN(nn.Module):
    def __init__(self):
        super().__init__()
        self.conv1 = nn.Conv1d(16, 64, 3, padding=1, bias=True)
        self.conv2 = nn.Conv1d(64, 32, 3, padding=1, bias=True)
        self.output = nn.Linear(32, 1, bias=True)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = torch.relu(self.conv1(x))
        x = torch.relu(self.conv2(x))
        return self.output(x.mean(dim=2))
