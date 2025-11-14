# logistic_scoring_transformer.py

import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.linear_model import LogisticRegression


class LogisticAlertScorer(BaseEstimator, TransformerMixin):
    """
    A transformer that fits a logistic regression model to score alerts
    using Bayesian Optimal hypertuning principles.
    """

    def __init__(
        self,
        feature_cols,
        C=1.0,
        class_weight="balanced",
        thresholds=None,
        random_state=42
    ):
        self.feature_cols = feature_cols
        self.C = C
        self.class_weight = class_weight
        self.thresholds = thresholds or {"high": 0.8, "medium": 0.5}
        self.random_state = random_state
        self.model_ = None

    def fit(self, X, y):
        X_feat = X[self.feature_cols]

        self.model_ = LogisticRegression(
            C=self.C,
            class_weight=self.class_weight,
            max_iter=2000,
            random_state=self.random_state
        )

        self.model_.fit(X_feat, y)
        return self

    def transform(self, X):
        if self.model_ is None:
            raise RuntimeError("Model not fitted.")

        X_copy = X.copy()
        X_feat = X_copy[self.feature_cols]

        raw_score = self.model_.decision_function(X_feat)
        proba = self.model_.predict_proba(X_feat)[:, 1]

        X_copy["alert_raw_score"] = raw_score
        X_copy["alert_probability"] = proba

        high = self.thresholds.get("high", 0.8)
        medium = self.thresholds.get("medium", 0.5)

        def _assign_level(p):
            if p >= high:
                return "HIGH"
            elif p >= medium:
                return "MEDIUM"
            else:
                return "LOW"

        X_copy["alert_level"] = X_copy["alert_probability"].apply(_assign_level)
        return X_copy

    