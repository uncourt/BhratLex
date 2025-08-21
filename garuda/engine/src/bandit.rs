use nalgebra::{DVector, DMatrix};
use anyhow::{Result, anyhow};
use crate::types::{DecisionAction, FeedbackRequest, EngineConfig};
use crate::queue::Queue;
use redis::AsyncCommands;

#[derive(Clone)]
pub struct LinUcb {
    // For simplicity, maintain A (dxd) and b (dx1) per arm
    arms: Vec<Arm>,
    dim: usize,
    alpha: f64,
    redis_client: redis::Client,
}

#[derive(Clone)]
struct Arm {
    a: DMatrix<f64>,
    b: DVector<f64>,
}

impl LinUcb {
    pub async fn load_or_init(cfg: &EngineConfig, _queue: &Queue) -> Result<Self> {
        let dim = 12; // number of features
        let alpha = 0.4;
        let client = redis::Client::open(cfg.redis_url.as_str())?;
        let mut conn = client.get_async_connection().await?;
        let key = "garuda:linucb";
        if let Ok(Some(blob)): Result<Option<Vec<u8>>, _> = redis::cmd("GET").arg(key).query_async(&mut conn).await {
            if let Ok(state) = bincode::deserialize::<Vec<(Vec<f64>, Vec<f64>)>>(&blob) {
                let arms = state.into_iter().map(|(a_flat, b_vec)| {
                    let a = DMatrix::from_row_slice(dim, dim, &a_flat);
                    let b = DVector::from_vec(b_vec);
                    Arm { a, b }
                }).collect();
                return Ok(Self { arms, dim, alpha, redis_client: client });
            }
        }
        // init identity
        let mut arms = Vec::new();
        for _ in 0..3 { // ALLOW, WARN, BLOCK order
            arms.push(Arm { a: DMatrix::<f64>::identity(dim, dim), b: DVector::<f64>::zeros(dim) });
        }
        let s = Self { arms, dim, alpha, redis_client: client };
        s.persist().await?;
        Ok(s)
    }

    pub fn select_action(&self, x: &crate::features::FeatureVector) -> DecisionAction {
        let fv = DVector::from_vec(vec![
            x.len_domain, x.num_dashes, x.num_digits, x.entropy, x.idn_homoglyph, x.typosquat_score, x.nrd, x.dynamic_dns, x.parked, x.cname_cloaking, x.dns_rebinding, x.coinblocklist_hit
        ]);
        let mut best_arm = 0usize; let mut best_ucb = f64::NEG_INFINITY;
        for (i, arm) in self.arms.iter().enumerate() {
            let a_inv = arm.a.clone().try_inverse().unwrap_or(DMatrix::identity(self.dim, self.dim));
            let theta = &a_inv * &arm.b;
            let est = theta.transpose() * &fv;
            let conf = self.alpha * ((&fv.transpose() * &a_inv * &fv)[(0,0)]).sqrt();
            let ucb = est[(0,0)] + conf;
            if ucb > best_ucb { best_ucb = ucb; best_arm = i; }
        }
        match best_arm { 0 => DecisionAction::ALLOW, 1 => DecisionAction::WARN, _ => DecisionAction::BLOCK }
    }

    pub async fn update_from_feedback(&mut self, fb: &FeedbackRequest) -> Result<()> {
        // For demo: uniformly update WARN arm with reward; in practice map decision_id to arm
        let arm_idx = 1usize;
        let fv = DVector::from_element(self.dim, 0.1); // approximate; full mapping would persist contexts per decision_id
        let r = fb.reward;
        // A += x x^T ; b += r x
        let xxt = &fv * fv.transpose();
        self.arms[arm_idx].a += xxt;
        self.arms[arm_idx].b += fv * r;
        self.persist().await?;
        Ok(())
    }

    async fn persist(&self) -> Result<()> {
        let mut conn = self.redis_client.get_async_connection().await?;
        let key = "garuda:linucb";
        let state: Vec<(Vec<f64>, Vec<f64>)> = self.arms.iter().map(|arm| (arm.a.as_slice().to_vec(), arm.b.as_slice().to_vec())).collect();
        let blob = bincode::serialize(&state)?;
        redis::cmd("SET").arg(key).arg(blob).query_async::<_, ()>(&mut conn).await?;
        Ok(())
    }
}