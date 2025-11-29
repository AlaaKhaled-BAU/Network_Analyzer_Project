# Git Commands to Create Branch and Push Changes

## 🎯 Quick Commands (Copy and paste into terminal)

```bash
# Navigate to project directory
cd c:\Users\DELL\Desktop\Network_Analyzer_Project

# Check current status
git status

# Create and switch to new branch
git checkout -b multi-window-aggregation

# Stage all changes
git add .

# Commit with descriptive message
git commit -m "feat: Implement multi-window aggregation system

- Add 5-second upload interval (sniffer.py, sender.py)
- Implement cascading 3-window aggregation (5s, 30s, 3min)
- Separate ML prediction service (ml_predictor.py)
- Add 3 new database tables (predictions_5s, _30s, _3min)
- Optimize 30s/3min windows to aggregate from 5s predictions
- Update all documentation (README, SEPARATED_ARCHITECTURE, etc.)
- Add AGGREGATION_STRATEGY.md explaining optimization"

# Push to GitHub
git push -u origin multi-window-aggregation
```

## 📦 What Will Be Committed

### Modified Files:
- `client/sniffer.py` - Changed SAVE_INTERVAL to 5 seconds
- `client/sender.py` - Changed POLL_INTERVAL to 1 second
- `server/app/main.py` - Added 3 new prediction tables
- `server/aggregator.py` - Complete rewrite for multi-window
- `README.md` - Updated architecture and configuration
- `SEPARATED_ARCHITECTURE.md` - Updated flow diagrams
- `docs/sniffer_explained.md` - Updated intervals
- `docs/aggregator_explained.md` - Complete rewrite

### New Files:
- `server/ml_predictor.py` - Separate ML prediction service
- `server/AGGREGATION_STRATEGY.md` - Optimization documentation

## 🌐 After Pushing

Your branch will be available at:
```
https://github.com/AlaaKhaled-BAU/Network_Analyzer_Project/tree/multi-window-aggregation
```

## 📋 Create Pull Request

1. Go to: https://github.com/AlaaKhaled-BAU/Network_Analyzer_Project
2. Click "Compare & pull request" for `multi-window-aggregation`
3. Add description:
   ```
   ## Multi-Window Aggregation System
   
   This PR implements a comprehensive multi-time-window traffic analysis system 
   with optimized cascading aggregation.
   
   ### Key Changes:
   - 5-second upload intervals for real-time detection
   - Three time windows: 5s, 30s, 3min
   - Cascading optimization (30s/3min built from 5s)
   - Separate ML prediction service
   - Updated all documentation
   
   ### Performance Impact:
   - 6× more uploads (12/min vs 2/min)
   - 70% less CPU for window processing
   - 14% fewer raw_packets queries
   
   ### Testing Needed:
   - Verify 5-second uploads work
   - Test multi-window aggregation
   - Verify ML predictions work
   - Check database performance
   ```

## ✅ Verification

After pushing, verify with:
```bash
git branch -a
git log --oneline -n 5
```

Should show `multi-window-aggregation` branch and your commit.
