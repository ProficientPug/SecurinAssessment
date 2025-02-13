from fastapi import FastAPI, HTTPException, Depends, Query, Request
from sqlalchemy import create_engine, Column, String, func, Float
from sqlalchemy.orm import declarative_base
from sqlalchemy import or_
from sqlalchemy.orm import sessionmaker, Session
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
import math
from datetime import datetime, timedelta


DATABASE_URL = "sqlite:///cve_database.db"
app = FastAPI()
Base = declarative_base()
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# SQLite Connection
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Database Models
class CVEEntry(Base):
    __tablename__ = "CVE_Entries"
    id = Column(String, primary_key=True, index=True)
    identifier = Column(String)
    published_date = Column(String)  
    last_modified_date = Column(String)
    status = Column(String)

class CVEDetail(Base):
    __tablename__ = "CVE_Details"
    id = Column(String, primary_key=True, index=True)
    description = Column(String)
    access_vector = Column(String)
    access_complexity = Column(String)
    authentication = Column(String)
    confidentiality_impact = Column(String)
    integrity_impact = Column(String)
    availability_impact = Column(String)
    exploitability_score = Column(Float)
    impact_score = Column(Float)
    criteria = Column(String)
    match_criteria_id = Column(String)
    vulnerability = Column(String)

# Dependency to Get DB Session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.get("/", response_class=HTMLResponse)
def home(
    request: Request,
    page: int = Query(1, ge=1),
    search_type: str = Query(None),
    search_value: str = Query(None),
    db: Session = Depends(get_db),
):
    print("received request")
    print(f"🔎 Received search_type: {search_type}, search_value: {search_value}, page: {page}")
    per_page = 50
    query = db.query(CVEEntry).join(CVEDetail, CVEEntry.id == CVEDetail.id)  # Join CVEEntry and CVEDetail
    if search_type and search_value:
        print(f"🛠 Applying filter: {search_type} = {search_value}")
        if search_type == "cve_id":
            search_pattern = f"%{search_value}%"  # Match any part of the string
            query = query.filter(CVEEntry.id.ilike(search_pattern))
        elif search_type == "year":
            try:
                query = query.filter(CVEEntry.published_date.startswith(search_value))
            except ValueError:
                print("Invalid Year Input")
        elif search_type == "last_modified":
            try:
                date_threshold = datetime.utcnow() - timedelta(days=int(search_value))
                query = query.filter(CVEEntry.last_modified_date >= date_threshold.strftime("%Y-%m-%d"))
            except ValueError:
                print("Invalid Last Modified Input")
    # Debugging: Print Raw Query
    print(f"SQL Query: {str(query.statement.compile(db.bind))}")

    total_count = query.count()
    total_pages = max(1, math.ceil(total_count / per_page))
    cves = query.offset((page - 1) * per_page).limit(per_page).all()

    print(f"Found {len(cves)} results")

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "cves": cves,
            "page": page,
            "total_pages": total_pages,
            "search_type": search_type,
            "search_value": search_value,
        },
    )
# CVE Details Page ("/{cve_id}")
@app.get("/{cve_id}", response_class=HTMLResponse)
def get_cve_details(request: Request, cve_id: str, db: Session = Depends(get_db)):
    if cve_id == "favicon.ico":
        return HTMLResponse(content="")

    cve_entry = db.query(CVEEntry).filter(CVEEntry.id == cve_id).first()
    cve_detail = db.query(CVEDetail).filter(CVEDetail.id == cve_id).first()

    if not cve_entry:
        raise HTTPException(status_code=404, detail="CVE not found")

    if not cve_detail:
        cve_detail = CVEDetail(
            id=cve_id,
            description="No additional details available.",
            access_vector="N/A",
            access_complexity="N/A",
            authentication="N/A",
            confidentiality_impact="N/A",
            integrity_impact="N/A",
            availability_impact="N/A",
            exploitability_score=None,
            impact_score=None,
            cvss_v2_score=None,
            cvss_v3_score=None,
            criteria="N/A",
            match_criteria_id="N/A",
            vulnerability="N/A",
        )

    return templates.TemplateResponse(
        "details.html",
        {"request": request, "cve_entry": cve_entry, "cve_detail": cve_detail},
    )
print(app.routes)